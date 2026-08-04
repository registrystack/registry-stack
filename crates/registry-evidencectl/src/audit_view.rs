//! Minimized local audit presentation delegated to the Evidence core.

use std::{
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use anyhow::{anyhow, Result};
use chrono::DateTime;
use clap::{ArgGroup, Args, Subcommand};
use serde::{Deserialize, Deserializer};

use crate::dev;

const CORE_VIEW_SCHEMA: &str = "registry.evidence.local-audit-operation/v1";
const MAX_CORE_OUTPUT_BYTES: usize = 256 * 1024;
const AUDIT_FAILED: &str = "local audit inspection failed";

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
    /// Show the last verified local operation after the service has stopped.
    #[arg(long)]
    last_operation: bool,

    /// Project root. Defaults to the current directory.
    #[arg(long, default_value = ".", hide = true)]
    project: PathBuf,

    #[arg(long, hide = true)]
    evidence_bin: Option<PathBuf>,
}

pub fn run(command: AuditCommand) -> Result<ExitCode> {
    match command {
        AuditCommand::Show(args) => show(args),
    }
}

fn show(args: ShowArgs) -> Result<ExitCode> {
    if !args.last_operation {
        return Err(failed());
    }
    let stopped = dev::load_stopped_state(&args.project).map_err(|_| failed())?;
    let evidence = dev::resolve_tool_binary(
        "evidence",
        args.evidence_bin.as_deref(),
        "EVIDENCECTL_TEST_EVIDENCE_BIN",
    )
    .map_err(|_| failed())?;
    let output = inspect_core(&evidence, &stopped.runtime_path)?;
    let view: CoreAuditOperation = serde_json::from_slice(&output).map_err(|_| failed())?;
    let rendered = render(&view, &stopped.questions)?;

    std::io::stdout()
        .lock()
        .write_all(rendered.as_bytes())
        .map_err(|_| failed())?;
    Ok(ExitCode::SUCCESS)
}

/// Read no more than the closed core output bound and retain nothing from a
/// failed child. Stderr is never inherited because it may contain protected
/// audit or deployment detail from a substituted binary.
fn inspect_core(evidence: &Path, runtime: &Path) -> Result<Vec<u8>> {
    let mut child = Command::new(evidence)
        .arg("--runtime")
        .arg(runtime)
        .arg("local-audit-last-operation")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| failed())?;
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
        return Err(failed());
    }
    let status = child.wait().map_err(|_| failed())?;
    if !status.success() {
        return Err(failed());
    }
    Ok(bytes)
}

fn render(view: &CoreAuditOperation, questions: &[dev::ReadyQuestionState]) -> Result<String> {
    let access = view.events.first().ok_or_else(failed)?;
    let question = questions
        .iter()
        .find(|question| {
            question.requirement_uri == access.requirement && question.purpose == access.purpose
        })
        .ok_or_else(failed)?;
    if view.schema != CORE_VIEW_SCHEMA
        || !valid_operation(&view.operation)
        || !valid_alias(&question.alias)
        || !valid_alias(&question.concept_alias)
        || !valid_purpose(&question.purpose)
        || !matches!(
            question.concept_form.as_str(),
            "boolean" | "controlled-category"
        )
        || !(1..=2).contains(&view.events.len())
    {
        return Err(failed());
    }

    validate_common(access, question)?;
    if access.phase != Phase::AccessAttempt
        || access.decision != Decision::Authorized
        || access.disclosed_concepts != Presence::Absent
        || access.evidence_id != Presence::Absent
    {
        return Err(failed());
    }

    let mut rendered = format!(
        "ACCESS AUTHORIZED {} {} requester={}\n",
        question.alias, question.purpose, access.requester_pseudonym
    );
    if view.events.len() == 1 {
        return Ok(rendered);
    }

    let release = &view.events[1];
    validate_common(release, question)?;
    if release.phase != Phase::DisclosureRelease
        || release.decision != Decision::Released
        || release.requirement != access.requirement
        || release.purpose != access.purpose
        || release.requester_pseudonym != access.requester_pseudonym
        || release.response_protection != access.response_protection
        || parse_time(&release.occurred_at)? < parse_time(&access.occurred_at)?
        || release.disclosed_concepts != Presence::Present(vec![question.concept_uri.clone()])
        || !matches!(
            &release.evidence_id,
            Presence::Present(value) if valid_uri(value)
        )
    {
        return Err(failed());
    }
    rendered.push_str(&format!("DISCLOSURE RELEASED {}\n", question.concept_alias));
    Ok(rendered)
}

fn validate_common(event: &CoreAuditEvent, question: &dev::ReadyQuestionState) -> Result<()> {
    if event.requirement != question.requirement_uri
        || event.purpose != question.purpose
        || event.response_protection != ResponseProtection::Signed
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

fn failed() -> anyhow::Error {
    anyhow!(AUDIT_FAILED)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CoreAuditOperation {
    schema: String,
    operation: String,
    events: Vec<CoreAuditEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CoreAuditEvent {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    AccessAttempt,
    DisclosureRelease,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Decision {
    Authorized,
    Released,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum ResponseProtection {
    Signed,
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
