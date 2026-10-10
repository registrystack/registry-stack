//! Minimized local audit presentation delegated to the Evidence core.

use std::{
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use anyhow::Result;
use chrono::DateTime;
use clap::{ArgGroup, Args, Subcommand};
use serde::{Deserialize, Deserializer};
use serde_json::json;

use crate::{dev, OutputFormat};

const CORE_VIEW_SCHEMA: &str = "registry.evidence.local-audit-operation/v2";
const MAX_CORE_OUTPUT_BYTES: usize = 256 * 1024;
/// The most the core's standard error is read, which is enough for any line
/// it names a failure with. More than that is no named failure.
const MAX_CORE_ERROR_BYTES: usize = 1024;
/// Builds the refusal a named core failure becomes.
type Refusal = fn() -> anyhow::Error;
/// The fixed lines the core names a failure with, and the refusal each one
/// becomes. A line is matched whole and never echoed.
const CORE_NAMED_FAILURES: [(&str, Refusal); 3] = [
    (
        "evidence: local audit inspection failed: the last operation is a request batch\n",
        request_batch,
    ),
    (
        "evidence: local audit inspection failed: an entry is not well formed\n",
        history_invalid,
    ),
    (
        "evidence: local audit inspection failed: a writer still holds the audit file\n",
        writer_running,
    ),
];
/// The core's exit status, with nothing written, for a stopped local audit
/// history that was read and retains no operation.
const CORE_NO_OPERATION_EXIT_CODE: i32 = 3;

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Show a minimized view of stopped local audit history.
    Show(ShowArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("view")
        .required(true)
        .multiple(false)
        .args(["last_operation"])
))]
pub struct ShowArgs {
    /// Show the last local operation recorded in the stopped local audit history.
    #[arg(long)]
    last_operation: bool,

    /// Project root. Defaults to the current directory.
    #[arg(long, default_value = ".", hide = true)]
    project: PathBuf,

    #[arg(long, hide = true)]
    evidence_bin: Option<PathBuf>,
}

pub fn run(command: AuditCommand, format: OutputFormat) -> Result<ExitCode> {
    match command {
        AuditCommand::Show(args) => show(args, format),
    }
}

fn show(args: ShowArgs, format: OutputFormat) -> Result<ExitCode> {
    if !args.last_operation {
        return Err(failed());
    }
    if no_local_session(&args.project) {
        return Err(no_stopped_session());
    }
    let stopped = dev::load_stopped_state(&args.project).map_err(|_| failed())?;
    let evidence = dev::resolve_tool_binary(
        "evidence",
        args.evidence_bin.as_deref(),
        "EVIDENCECTL_TEST_EVIDENCE_BIN",
    )
    .map_err(|_| unavailable())?;
    let output = inspect_core(&evidence, &stopped.runtime_path)?;
    let view: CoreAuditOperation = serde_json::from_slice(&output).map_err(|_| failed())?;
    let rendered = render(&view, &stopped.questions)?;

    match format {
        OutputFormat::Human => std::io::stdout()
            .lock()
            .write_all(rendered.as_bytes())
            .map_err(|_| failed())?,
        // The core document is the minimized audit view the Evidence binary
        // itself published, and `render` has already validated it against the
        // closed shape, so the report embeds it beside the same refusal-safe
        // lines the human renderer prints.
        OutputFormat::Json => {
            let operation: serde_json::Value =
                serde_json::from_slice(&output).map_err(|_| failed())?;
            let report = crate::command_report(
                "audit show",
                json!({
                    "operation": operation,
                    "rendered": rendered.lines().collect::<Vec<_>>(),
                }),
            );
            crate::print_report(&report);
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Read no more than the closed core output bound and retain nothing from a
/// failed child. Stderr is never inherited or echoed because it may contain
/// protected audit or deployment detail from a substituted binary; a bounded
/// read of it is only compared whole against the fixed lines the core names a
/// failure with.
fn inspect_core(evidence: &Path, runtime: &Path) -> Result<Vec<u8>> {
    let mut child = Command::new(evidence)
        .arg("local-audit-last-operation")
        .arg("--runtime-config")
        .arg(runtime)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| unavailable())?;
    // Drained beside stdout, so a child that fills one pipe never blocks the
    // other. Past the bound the rest is discarded, never retained.
    let stderr = child.stderr.take().ok_or_else(failed)?;
    let stderr = std::thread::spawn(move || {
        let mut named = Vec::with_capacity(MAX_CORE_ERROR_BYTES);
        let mut stderr = stderr;
        let within = (&mut stderr)
            .take(MAX_CORE_ERROR_BYTES as u64 + 1)
            .read_to_end(&mut named)
            .is_ok();
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
        within.then_some(named)
    });
    let mut bytes = Vec::with_capacity(MAX_CORE_OUTPUT_BYTES.min(8192));
    let read = child
        .stdout
        .take()
        .ok_or_else(failed)?
        .take((MAX_CORE_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() > MAX_CORE_OUTPUT_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        let _ = stderr.join();
        return Err(failed());
    }
    let status = child.wait().map_err(|_| failed())?;
    let named = stderr.join().ok().flatten();
    if status.code() == Some(CORE_NO_OPERATION_EXIT_CODE) && bytes.is_empty() {
        return Err(no_operation());
    }
    if !status.success() {
        return Err(bytes
            .is_empty()
            .then(|| named.as_deref().and_then(named_core_failure))
            .flatten()
            .unwrap_or_else(failed));
    }
    Ok(bytes)
}

/// The refusal a failed core named with one of its fixed lines, if its whole
/// standard error is exactly that line.
fn named_core_failure(stderr: &[u8]) -> Option<anyhow::Error> {
    CORE_NAMED_FAILURES
        .iter()
        .find(|(line, _)| line.as_bytes() == stderr)
        .map(|(_, refusal)| refusal())
}

fn render(view: &CoreAuditOperation, questions: &[dev::ReadyQuestionState]) -> Result<String> {
    if view.schema != CORE_VIEW_SCHEMA || !valid_operation(&view.operation) {
        return Err(failed());
    }

    let mut rendered = render_events(view, questions)?;
    if view.unmatched_earlier_operations > 0 {
        rendered.push_str(&format!(
            "EARLIER OPERATIONS WITHOUT AN OUTCOME count={}\n",
            view.unmatched_earlier_operations
        ));
    }
    Ok(rendered)
}

fn render_events(
    view: &CoreAuditOperation,
    questions: &[dev::ReadyQuestionState],
) -> Result<String> {
    if let [CoreAuditEvent::Refusal(refusal)] = view.events.as_slice() {
        return render_refusal(refusal);
    }
    let authorized = view
        .events
        .iter()
        .map(|event| match event {
            CoreAuditEvent::Authorized(event) => Ok(event),
            CoreAuditEvent::Refusal(_) => Err(failed()),
        })
        .collect::<Result<Vec<_>>>()?;
    // One access entry per source call, then the terminal entry when the
    // operation ended.
    match authorized.split_last() {
        Some((terminal, accesses))
            if terminal.phase != Phase::AccessAttempt && !accesses.is_empty() =>
        {
            render_authorized(accesses, Some(terminal), questions)
        }
        Some(_) => render_authorized(&authorized, None, questions),
        None => Err(failed()),
    }
}

fn render_refusal(refusal: &CoreRefusalAuditEvent) -> Result<String> {
    if refusal.phase == Phase::Unrecognized || refusal.decision == Decision::Unrecognized {
        return Err(unrecognized_outcome());
    }
    if refusal.phase != Phase::Denial
        || refusal.decision != Decision::NotAuthorized
        || refusal.safe_error_category != SafeErrorCategory::NotAuthorized
        || !valid_pseudonym(&refusal.requester_pseudonym)
    {
        return Err(failed());
    }
    parse_time(&refusal.occurred_at)?;
    Ok(format!(
        "ACCESS REFUSED requester={} reason=not-authorized\n",
        refusal.requester_pseudonym
    ))
}

fn render_authorized(
    accesses: &[&CoreAuthorizedAuditEvent],
    terminal: Option<&CoreAuthorizedAuditEvent>,
    questions: &[dev::ReadyQuestionState],
) -> Result<String> {
    if accesses
        .iter()
        .copied()
        .chain(terminal)
        .any(|event| event.phase == Phase::Unrecognized || event.decision == Decision::Unrecognized)
    {
        return Err(unrecognized_outcome());
    }
    let (access, _) = accesses.split_first().ok_or_else(failed)?;
    let question = questions
        .iter()
        .find(|question| {
            question.requirement_uri == access.requirement && question.purpose == access.purpose
        })
        .ok_or_else(failed)?;
    if !valid_alias(&question.alias)
        || question.concepts.is_empty()
        || question.concepts.len() > 16
        || question.concepts.iter().any(|concept| {
            !valid_alias(&concept.alias)
                || !valid_uri(&concept.uri)
                || !matches!(
                    concept.form.as_str(),
                    "boolean"
                        | "controlled-category"
                        | "bounded-identifier"
                        | "bounded-integer"
                        | "reviewed-structured-value"
                )
        })
        || !valid_purpose(&question.purpose)
    {
        return Err(failed());
    }

    let mut rendered = String::new();
    let mut previous: Option<&CoreAuthorizedAuditEvent> = None;
    for stage in accesses {
        validate_common(stage, question)?;
        if stage.phase != Phase::AccessAttempt
            || stage.decision != Decision::Authorized
            || stage.requester_pseudonym != access.requester_pseudonym
            || stage.response_protection != access.response_protection
            || stage.disclosed_concepts != Presence::Absent
            || stage.evidence_id != Presence::Absent
        {
            return Err(failed());
        }
        if let Some(previous) = previous {
            if parse_time(&stage.occurred_at)? < parse_time(&previous.occurred_at)? {
                return Err(failed());
            }
        }
        previous = Some(stage);
        rendered.push_str(&format!(
            "ACCESS AUTHORIZED {} {} requester={}\n",
            question.alias, question.purpose, stage.requester_pseudonym
        ));
    }
    let access = previous.ok_or_else(failed)?;
    let Some(terminal) = terminal else {
        return Ok(rendered);
    };
    if terminal.phase != Phase::DisclosureRelease {
        rendered.push_str(&render_unreleased(access, terminal, question)?);
        return Ok(rendered);
    }
    let release = terminal;

    validate_common(release, question)?;
    if release.phase != Phase::DisclosureRelease
        || release.decision != Decision::Released
        || release.requirement != access.requirement
        || release.purpose != access.purpose
        || release.requester_pseudonym != access.requester_pseudonym
        || release.response_protection != access.response_protection
        || parse_time(&release.occurred_at)? < parse_time(&access.occurred_at)?
        || release.disclosed_concepts
            != Presence::Present(
                question
                    .concepts
                    .iter()
                    .map(|concept| concept.uri.clone())
                    .collect(),
            )
        || !matches!(
            &release.evidence_id,
            Presence::Present(value) if valid_uri(value)
        )
    {
        return Err(failed());
    }
    rendered.push_str(&format!(
        "DISCLOSURE RELEASED {}\n",
        question
            .concepts
            .iter()
            .map(|concept| concept.alias.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    Ok(rendered)
}

/// The line for an operation that ended after its access without releasing:
/// a denial the evaluation decided, or a transient failure. Either carries
/// the access's context and no release field.
fn render_unreleased(
    access: &CoreAuthorizedAuditEvent,
    terminal: &CoreAuthorizedAuditEvent,
    question: &dev::ReadyQuestionState,
) -> Result<String> {
    validate_common(terminal, question)?;
    let outcome = match (terminal.phase, terminal.decision) {
        (
            Phase::Denial,
            Decision::NoMatch | Decision::Ambiguous | Decision::Unresolved | Decision::FactMissing,
        ) => "DISCLOSURE DENIED",
        (
            Phase::TransientFailure,
            Decision::DependencyFailure | Decision::EvaluationFailure | Decision::SigningFailure,
        ) => "TRANSIENT FAILURE",
        _ => return Err(failed()),
    };
    if terminal.requester_pseudonym != access.requester_pseudonym
        || terminal.response_protection != access.response_protection
        || terminal.disclosed_concepts != Presence::Absent
        || terminal.evidence_id != Presence::Absent
        || parse_time(&terminal.occurred_at)? < parse_time(&access.occurred_at)?
    {
        return Err(failed());
    }
    Ok(format!(
        "{outcome} reason={}\n",
        terminal.decision.reason().ok_or_else(failed)?
    ))
}

fn validate_common(
    event: &CoreAuthorizedAuditEvent,
    question: &dev::ReadyQuestionState,
) -> Result<()> {
    if event.requirement != question.requirement_uri
        || event.purpose != question.purpose
        || !matches!(
            event.response_protection,
            ResponseProtection::Signed | ResponseProtection::SdJwtVc
        )
        || !valid_pseudonym(&event.requester_pseudonym)
    {
        return Err(failed());
    }
    parse_time(&event.occurred_at)?;
    Ok(())
}

fn parse_time(value: &str) -> Result<chrono::DateTime<chrono::FixedOffset>> {
    if value.len() > 64 || value.chars().any(char::is_control) {
        return Err(failed());
    }
    DateTime::parse_from_rfc3339(value).map_err(|_| failed())
}

fn valid_operation(value: &str) -> bool {
    (16..=128).contains(&value.len()) && !value.chars().any(char::is_control)
}

fn valid_alias(value: &str) -> bool {
    valid_local_name(value, 128, false)
}

fn valid_purpose(value: &str) -> bool {
    valid_local_name(value, 128, true)
}

fn valid_local_name(value: &str, maximum: usize, colon: bool) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= maximum
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-')
                || (colon && byte == b':')
        })
}

fn valid_pseudonym(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("hmac-sha256:v") else {
        return false;
    };
    let Some((version, digest)) = rest.split_once(':') else {
        return false;
    };
    !version.is_empty()
        && !version.starts_with('0')
        && version.bytes().all(|byte| byte.is_ascii_digit())
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_uri(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && url::Url::parse(value).is_ok()
}

/// Whether the project holds no local session directory at all, neither the
/// session nor one set aside by an interrupted restart, so there is no
/// stopped audit history to inspect. Any other state, including a session
/// directory that lost its state file, goes through the full stopped-state
/// validation.
fn no_local_session(project: &Path) -> bool {
    ["dev", dev::RETAINED_STOPPED_SESSION].iter().all(|name| {
        matches!(
            std::fs::symlink_metadata(project.join(".evidence").join(name)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
    })
}

fn no_stopped_session() -> anyhow::Error {
    refusal(
        "evidence.audit.no-stopped-session",
        "local development project",
        "This project has no stopped local session, so it has no local audit history to show.",
        "Run evidencectl dev start, send a request, run evidencectl dev stop, then rerun audit show.",
    )
}

fn no_operation() -> anyhow::Error {
    refusal(
        "evidence.audit.no-operation",
        "local audit history",
        "The stopped local audit history was read and records no operation.",
        "Send a request to a local session started with evidencectl dev start, run evidencectl dev stop, then rerun audit show.",
    )
}

fn request_batch() -> anyhow::Error {
    refusal(
        "evidence.audit.request-batch",
        "local audit history",
        "The last operation in the stopped local audit history is a request batch, which audit show does not display.",
        "Send one single-item request to a local session started with evidencectl dev start, run evidencectl dev stop, then rerun audit show.",
    )
}

fn history_invalid() -> anyhow::Error {
    refusal(
        "evidence.audit.history-invalid",
        "local audit history",
        "The stopped local audit history holds an entry that is not a well-formed Evidence audit entry.",
        "If Evidence stopped abruptly, run evidencectl dev start and evidencectl dev stop once so the writer moves a torn final line aside, then rerun audit show; otherwise archive the session's audit files before starting a fresh session.",
    )
}

fn writer_running() -> anyhow::Error {
    refusal(
        "evidence.audit.writer-running",
        "local audit history",
        "A running Evidence process still holds the local audit file.",
        "Stop the local session with evidencectl dev stop, then rerun audit show.",
    )
}

fn unrecognized_outcome() -> anyhow::Error {
    refusal(
        "evidence.audit.unrecognized-outcome",
        "local audit history",
        "The last local operation records an outcome this evidencectl version does not recognize.",
        "Install the evidence and evidencectl binaries of the same version, then rerun audit show.",
    )
}

/// The one closed class for every other failure. It names no cause, because
/// the detail may come from protected audit or deployment state.
fn failed() -> anyhow::Error {
    refusal(
        "evidence.audit.inspection-failed",
        "local audit history",
        "Evidence could not read the stopped local audit history.",
        "Stop the local session with evidencectl dev stop and rerun audit show; if it is already stopped, its retained audit history could not be read.",
    )
}

/// The evidence binary that reads the history could not be found or started:
/// an unavailable process, not a refused input.
fn unavailable() -> anyhow::Error {
    closed_failure(
        true,
        "evidence.audit.runtime-unavailable",
        "evidence binary",
        "Evidence adopter tooling could not start the evidence binary that reads the local audit history.",
        "Install the evidence binary of this evidencectl version on PATH, then rerun evidencectl audit show --last-operation.",
    )
}

fn refusal(code: &str, artifact: &str, message: &str, suggested_action: &str) -> anyhow::Error {
    closed_failure(false, code, artifact, message, suggested_action)
}

fn closed_failure(
    operational: bool,
    code: &str,
    artifact: &str,
    message: &str,
    suggested_action: &str,
) -> anyhow::Error {
    crate::SafeCliFailure {
        operational,
        code: code.to_owned(),
        artifact: artifact.to_owned(),
        path: "$".to_owned(),
        message: message.to_owned(),
        suggested_action: suggested_action.to_owned(),
        cause: None,
    }
    .into()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CoreAuditOperation {
    schema: String,
    operation: String,
    events: Vec<CoreAuditEvent>,
    unmatched_earlier_operations: u64,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CoreAuditEvent {
    Authorized(CoreAuthorizedAuditEvent),
    Refusal(CoreRefusalAuditEvent),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CoreAuthorizedAuditEvent {
    occurred_at: String,
    phase: Phase,
    decision: Decision,
    requirement: String,
    purpose: String,
    requester_pseudonym: String,
    response_protection: ResponseProtection,
    #[serde(default, deserialize_with = "deserialize_presence")]
    disclosed_concepts: Presence<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_presence")]
    evidence_id: Presence<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CoreRefusalAuditEvent {
    occurred_at: String,
    phase: Phase,
    decision: Decision,
    requester_pseudonym: String,
    safe_error_category: SafeErrorCategory,
}

/// The core's closed phase vocabulary. A phase a later core adds reads as
/// `Unrecognized`, which is named as such rather than refused as unreadable.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    AccessAttempt,
    DisclosureRelease,
    Denial,
    TransientFailure,
    #[serde(other)]
    Unrecognized,
}

/// The core's closed decision vocabulary, with the same fallback as [`Phase`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Decision {
    Authorized,
    Released,
    NotAuthorized,
    NoMatch,
    Ambiguous,
    Unresolved,
    FactMissing,
    DependencyFailure,
    EvaluationFailure,
    SigningFailure,
    #[serde(other)]
    Unrecognized,
}

impl Decision {
    /// The reason a terminal line names for a decision that ended an
    /// operation without a release.
    fn reason(self) -> Option<&'static str> {
        Some(match self {
            Self::NoMatch => "no-match",
            Self::Ambiguous => "ambiguous",
            Self::Unresolved => "unresolved",
            Self::FactMissing => "fact-missing",
            Self::DependencyFailure => "dependency-failure",
            Self::EvaluationFailure => "evaluation-failure",
            Self::SigningFailure => "signing-failure",
            Self::Authorized | Self::Released | Self::NotAuthorized | Self::Unrecognized => {
                return None
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum SafeErrorCategory {
    NotAuthorized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum ResponseProtection {
    Signed,
    SdJwtVc,
}

#[derive(Debug, Default, Eq, PartialEq)]
enum Presence<T> {
    #[default]
    Absent,
    Present(T),
}

fn deserialize_presence<'de, D, T>(deserializer: D) -> Result<Presence<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Presence::Present)
}
