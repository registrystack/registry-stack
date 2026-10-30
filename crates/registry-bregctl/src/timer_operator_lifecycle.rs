// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand, ValueEnum};
use registry_breg::timer_operator::{
    TimerControlRequest, TimerControlTransition, TimerListRequest, TimerOccurrenceDetail,
    TimerOccurrencePage, TimerOccurrenceState, TimerOperatorError, TimerOperatorService,
    TimerRetryOutcome, TimerRetryRequest, TimerStatus, MAXIMUM_TIMER_LIST_LIMIT,
};
use serde_json::json;
use uuid::Uuid;

use super::{
    diagnostic, render_report, tool_diagnostic, write_ctl_report, write_failure, write_result,
    DiagnosticArtifact, FailureReport, OutputFormat, SuggestedAction,
};

#[derive(Debug, Args)]
pub(super) struct TimerArgs {
    #[command(subcommand)]
    command: TimerCommand,
}

#[derive(Debug, Subcommand)]
enum TimerCommand {
    /// Report bounded scheduler health and retained occurrence counts.
    Status(TimerRuntimeArgs),
    /// List a bounded page of value-free retained occurrences.
    List(TimerListArgs),
    /// Show one retained occurrence and its bounded attempt history.
    Show(TimerShowArgs),
    /// Grant one exact technically blocked occurrence one additional attempt.
    Retry(TimerRetryArgs),
    /// Pause new timer claims under an exact control epoch.
    Pause(TimerControlArgs),
    /// Resume timer claims, including release from adoption hold.
    Resume(TimerControlArgs),
}

#[derive(Debug, Args)]
struct TimerRuntimeArgs {
    /// Runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum TimerStateArg {
    Pending,
    Leased,
    Completed,
    Refused,
    Blocked,
    Cancelled,
    Superseded,
    Missed,
}

impl From<TimerStateArg> for TimerOccurrenceState {
    fn from(value: TimerStateArg) -> Self {
        match value {
            TimerStateArg::Pending => Self::Pending,
            TimerStateArg::Leased => Self::Leased,
            TimerStateArg::Completed => Self::Completed,
            TimerStateArg::Refused => Self::Refused,
            TimerStateArg::Blocked => Self::Blocked,
            TimerStateArg::Cancelled => Self::Cancelled,
            TimerStateArg::Superseded => Self::Superseded,
            TimerStateArg::Missed => Self::Missed,
        }
    }
}

#[derive(Debug, Args)]
struct TimerListArgs {
    /// Runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
    /// Retained occurrence state.
    #[arg(long, value_name = "STATE")]
    state: Option<TimerStateArg>,
    /// Compiled Record type identifier.
    #[arg(long = "record-type", value_name = "ID")]
    record_type: Option<String>,
    /// Compiled timer identifier.
    #[arg(long, value_name = "ID")]
    timer: Option<String>,
    /// Opaque cursor returned by the previous page.
    #[arg(long, value_name = "CURSOR")]
    after_cursor: Option<String>,
    /// Page size, at most the runtime's fixed operator limit.
    #[arg(long, value_name = "COUNT")]
    limit: Option<u16>,
}

#[derive(Debug, Args)]
struct TimerShowArgs {
    /// Runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
    /// Exact retained occurrence identifier.
    #[arg(long, value_name = "UUID")]
    occurrence_id: Uuid,
}

#[derive(Debug, Args)]
struct TimerRetryArgs {
    /// Runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
    /// Exact retained occurrence identifier.
    #[arg(long, value_name = "UUID")]
    occurrence_id: Uuid,
    /// Cumulative executed-attempt count observed by the operator.
    #[arg(long, value_name = "COUNT")]
    expected_attempt_count: u32,
    /// Bounded operator change reference, retained only as a keyed hash.
    #[arg(long, value_name = "REFERENCE")]
    operator_reference: String,
    /// Bounded reason, retained only as a keyed hash.
    #[arg(long, value_name = "TEXT")]
    reason: String,
}

#[derive(Debug, Args)]
struct TimerControlArgs {
    /// Runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
    /// Durable control epoch observed by the operator.
    #[arg(long, value_name = "EPOCH")]
    expected_control_epoch: i64,
    /// Bounded operator change reference, retained only as a keyed hash.
    #[arg(long, value_name = "REFERENCE")]
    operator_reference: String,
    /// Bounded reason, retained only as a keyed hash.
    #[arg(long, value_name = "TEXT")]
    reason: String,
}

enum TimerOutcome {
    Status(TimerStatus),
    List(TimerOccurrencePage),
    Show(Box<TimerOccurrenceDetail>),
    Retry(TimerRetryOutcome),
    Control(TimerControlTransition),
}

pub(super) fn run(
    args: TimerArgs,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let command = args.command.name();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let outcome = runtime
        .map_err(|_| TimerOperatorError::DatabaseUnavailable)
        .and_then(|runtime| runtime.block_on(args.command.execute()));
    match outcome {
        Ok(outcome) => write_success(command, &outcome, format, stdout, stderr),
        Err(error) => write_failure(&timer_failure(command, error), format, stdout, stderr),
    }
}

impl TimerCommand {
    const fn name(&self) -> &'static str {
        match self {
            Self::Status(_) => "timer status",
            Self::List(_) => "timer list",
            Self::Show(_) => "timer show",
            Self::Retry(_) => "timer retry",
            Self::Pause(_) => "timer pause",
            Self::Resume(_) => "timer resume",
        }
    }

    async fn execute(self) -> Result<TimerOutcome, TimerOperatorError> {
        match self {
            Self::Status(args) => {
                let service =
                    TimerOperatorService::from_runtime_config(&args.runtime_config).await?;
                service.status().await.map(TimerOutcome::Status)
            }
            Self::List(args) => {
                let request = TimerListRequest {
                    state: args.state.map(Into::into),
                    record_type: args.record_type.as_deref(),
                    timer: args.timer.as_deref(),
                    after_cursor: args.after_cursor.as_deref(),
                    limit: args.limit,
                };
                request.validate(MAXIMUM_TIMER_LIST_LIMIT)?;
                let service =
                    TimerOperatorService::from_runtime_config(&args.runtime_config).await?;
                service.list(request).await.map(TimerOutcome::List)
            }
            Self::Show(args) => {
                let service =
                    TimerOperatorService::from_runtime_config(&args.runtime_config).await?;
                service
                    .show(args.occurrence_id)
                    .await
                    .map(Box::new)
                    .map(TimerOutcome::Show)
            }
            Self::Retry(args) => {
                let request = TimerRetryRequest {
                    occurrence_id: args.occurrence_id,
                    expected_attempt_count: args.expected_attempt_count,
                    operator_reference: &args.operator_reference,
                    reason: &args.reason,
                };
                request.validate()?;
                let service =
                    TimerOperatorService::from_runtime_config(&args.runtime_config).await?;
                service.retry(request).await.map(TimerOutcome::Retry)
            }
            Self::Pause(args) => execute_control(args, true).await,
            Self::Resume(args) => execute_control(args, false).await,
        }
    }
}

async fn execute_control(
    args: TimerControlArgs,
    pause: bool,
) -> Result<TimerOutcome, TimerOperatorError> {
    let request = TimerControlRequest {
        expected_control_epoch: args.expected_control_epoch,
        operator_reference: &args.operator_reference,
        reason: &args.reason,
    };
    request.validate()?;
    let service = TimerOperatorService::from_runtime_config(&args.runtime_config).await?;
    let transition = if pause {
        service.pause(request).await?
    } else {
        service.resume(request).await?
    };
    Ok(TimerOutcome::Control(transition))
}

fn timer_failure(command: &'static str, error: TimerOperatorError) -> FailureReport {
    let code = error.problem_code();
    let (path, message, artifact, action) = match error {
        TimerOperatorError::RuntimeConfigPath => (
            "runtimeConfig",
            "the runtime configuration must be an absolute path",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectCommandUsage,
        ),
        TimerOperatorError::RuntimeConfigRefused => (
            "runtimeConfig",
            "the runtime configuration was refused; correct its structure and referenced configuration inputs, then retry",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        TimerOperatorError::PackageRefused => (
            "package",
            "the active timer package was refused; verify the configured package and database activation binding",
            DiagnosticArtifact::TimerOperator,
            SuggestedAction::VerifyPackageBinding,
        ),
        TimerOperatorError::DatabaseUnavailable => (
            "database",
            "the timer store is unavailable; verify the runtime database, active package binding, and timer protocol",
            DiagnosticArtifact::TimerOperator,
            SuggestedAction::VerifyTimerOperator,
        ),
        TimerOperatorError::OutcomeUnresolved => (
            "timer",
            "the database did not acknowledge the timer transition outcome; inspect timer status or show before retrying because the transition may have committed",
            DiagnosticArtifact::TimerOperator,
            SuggestedAction::VerifyTimerOperator,
        ),
        TimerOperatorError::OperationRefused => (
            "timer",
            "the timer operation was refused; inspect timer status and the current occurrence before retrying",
            DiagnosticArtifact::TimerOperator,
            SuggestedAction::VerifyTimerOperator,
        ),
        TimerOperatorError::OccurrenceNotFound => (
            "occurrenceId",
            "the occurrence was not found in retained timer history",
            DiagnosticArtifact::TimerOperator,
            SuggestedAction::VerifyTimerOperator,
        ),
        TimerOperatorError::RetryIneligible => (
            "occurrenceId",
            "the occurrence is not an eligible current technical block with an unexpired execution window",
            DiagnosticArtifact::TimerOperator,
            SuggestedAction::VerifyTimerOperator,
        ),
        TimerOperatorError::OccurrenceChanged => (
            "expectedAttemptCount",
            "the occurrence changed after it was inspected; show it again before deciding whether to retry",
            DiagnosticArtifact::TimerOperator,
            SuggestedAction::VerifyTimerOperator,
        ),
        TimerOperatorError::ControlEpochMismatch => (
            "expectedControlEpoch",
            "the timer control epoch changed after it was inspected; run timer status and retry with the current epoch",
            DiagnosticArtifact::TimerOperator,
            SuggestedAction::VerifyTimerOperator,
        ),
        TimerOperatorError::InProgress => (
            "timer",
            "another timer operation is in progress; inspect status before retrying",
            DiagnosticArtifact::TimerOperator,
            SuggestedAction::VerifyTimerOperator,
        ),
        TimerOperatorError::AuditUnavailable => (
            "audit",
            "the timer audit record is unavailable; the requested transition may have committed if its outcome append failed, so inspect timer status or show before retrying",
            DiagnosticArtifact::TimerOperator,
            SuggestedAction::VerifyTimerOperator,
        ),
        TimerOperatorError::ProtocolUnsupported => (
            "protocolVersion",
            "the persisted timer protocol is not supported by this bregctl build; use the matching runtime and package version",
            DiagnosticArtifact::TimerOperator,
            SuggestedAction::VerifyTimerOperator,
        ),
    };
    FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, message),
            artifact,
            action,
        )],
    }
}

fn write_success(
    command: &'static str,
    outcome: &TimerOutcome,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        let body = match outcome {
            TimerOutcome::Status(status) => json!({"ok":true,"command":command,"timer":status}),
            TimerOutcome::List(page) => json!({"ok":true,"command":command,"page":page}),
            TimerOutcome::Show(occurrence) => {
                json!({"ok":true,"command":command,"occurrence":occurrence})
            }
            TimerOutcome::Retry(retry) => json!({"ok":true,"command":command,"retry":retry}),
            TimerOutcome::Control(control) => {
                json!({"ok":true,"command":command,"control":control})
            }
        };
        write_ctl_report(&mut *stdout, &body)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        write_human(outcome, stdout)
    };
    write_result(result, stderr)
}

fn write_human(outcome: &TimerOutcome, stdout: &mut dyn Write) -> io::Result<()> {
    match outcome {
        TimerOutcome::Status(status) => render_report(
            "Read the bounded Record-timer operator status.",
            &[
                ("protocol version", status.protocol_version.to_string()),
                ("control state", status.control_state.as_str().to_owned()),
                ("control epoch", status.control_epoch.to_string()),
                ("instance epoch", status.instance_epoch.to_string()),
                (
                    "observed lease owners",
                    status.observed_lease_owner_count.to_string(),
                ),
                ("stale revisions", status.stale_revision_count.to_string()),
                (
                    "oldest due lag seconds",
                    status
                        .oldest_due_lag_seconds
                        .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                ),
                ("counts truncated", status.counts_truncated.to_string()),
                ("pending", status.occurrence_counts.pending.to_string()),
                ("leased", status.occurrence_counts.leased.to_string()),
                ("completed", status.occurrence_counts.completed.to_string()),
                ("refused", status.occurrence_counts.refused.to_string()),
                ("blocked", status.occurrence_counts.blocked.to_string()),
                ("cancelled", status.occurrence_counts.cancelled.to_string()),
                (
                    "superseded",
                    status.occurrence_counts.superseded.to_string(),
                ),
                ("missed", status.occurrence_counts.missed.to_string()),
                (
                    "technical blocks",
                    status.block_counts.technical.to_string(),
                ),
                (
                    "configuration blocks",
                    status.block_counts.configuration.to_string(),
                ),
                (
                    "claim batch maximum",
                    status.limits.claim_batch_maximum.to_string(),
                ),
                (
                    "stale batch maximum",
                    status.limits.stale_revision_batch_maximum.to_string(),
                ),
                (
                    "elapsed-window batch maximum",
                    status.limits.elapsed_window_batch_maximum.to_string(),
                ),
                (
                    "maximum concurrent attempts",
                    status.limits.maximum_concurrent_attempts.to_string(),
                ),
                (
                    "operator list maximum",
                    status.limits.operator_list_maximum.to_string(),
                ),
            ],
            stdout,
        ),
        TimerOutcome::List(page) => {
            let mut lines = super::report::Lines::new();
            lines.lead("Listed bounded, value-free Record-timer occurrences.");
            lines.pairs(&[("occurrences", page.occurrences.len().to_string())]);
            if let Some(cursor) = &page.next_cursor {
                lines.pairs(&[("next cursor", cursor.clone())]);
            }
            for occurrence in &page.occurrences {
                lines.blank();
                lines.item(&format!("occurrence {}", occurrence.occurrence_id));
                lines.pairs_at(1, &occurrence_pairs(occurrence));
            }
            stdout.write_all(lines.finish().as_bytes())
        }
        TimerOutcome::Show(detail) => {
            let mut lines = super::report::Lines::new();
            lines.lead("Read one retained Record-timer occurrence.");
            lines.pairs(&[("occurrence", detail.summary.occurrence_id.clone())]);
            lines.pairs(&occurrence_pairs(&detail.summary));
            lines.pairs(&[
                ("action revision", detail.action_revision.clone()),
                ("created activation", detail.created_activation_id.clone()),
                (
                    "current policy activation",
                    optional(detail.current_policy_activation_id.as_deref()),
                ),
                (
                    "executed activation",
                    optional(detail.executed_activation_id.as_deref()),
                ),
                ("control epoch", optional_number(detail.control_epoch)),
                ("instance epoch", optional_number(detail.instance_epoch)),
                ("claim epoch", optional_number(detail.claim_epoch)),
                (
                    "receipt reference",
                    optional(detail.receipt_reference.as_deref()),
                ),
                ("attempts truncated", detail.attempts_truncated.to_string()),
            ]);
            for attempt in &detail.attempts {
                lines.blank();
                lines.item(&format!("attempt {}", attempt.attempt));
                lines.pairs_at(
                    1,
                    &[
                        ("started at", attempt.started_at.to_rfc3339()),
                        (
                            "finished at",
                            attempt
                                .finished_at
                                .map(|value| value.to_rfc3339())
                                .unwrap_or_else(|| "none".to_owned()),
                        ),
                        (
                            "block kind",
                            attempt
                                .block_kind
                                .map(|value| value.as_str())
                                .unwrap_or("none")
                                .to_owned(),
                        ),
                        (
                            "outcome",
                            attempt
                                .outcome_code
                                .map(|value| value.as_str())
                                .unwrap_or("none")
                                .to_owned(),
                        ),
                        (
                            "technical code",
                            attempt
                                .technical_code
                                .map(|value| value.as_str())
                                .unwrap_or("none")
                                .to_owned(),
                        ),
                    ],
                );
            }
            stdout.write_all(lines.finish().as_bytes())
        }
        TimerOutcome::Retry(retry) => render_report(
            "Queued one additional technical retry allowance.",
            &[
                ("occurrence", retry.occurrence_id.clone()),
                ("state", retry.state.as_str().to_owned()),
                ("executed attempts", retry.attempt_count.to_string()),
                ("retry allowance", retry.retry_allowance.to_string()),
                ("control epoch", retry.control_epoch.to_string()),
            ],
            stdout,
        ),
        TimerOutcome::Control(control) => render_report(
            if control.changed {
                "Changed the Record-timer control state."
            } else {
                "The Record-timer control state already matched."
            },
            &[
                (
                    "previous control epoch",
                    control.previous_control_epoch.to_string(),
                ),
                ("control epoch", control.control_epoch.to_string()),
                ("state", control.state.as_str().to_owned()),
                ("changed", control.changed.to_string()),
            ],
            stdout,
        ),
    }
}

fn occurrence_pairs(
    occurrence: &registry_breg::timer_operator::TimerOccurrenceSummary,
) -> Vec<(&'static str, String)> {
    vec![
        ("Record type", occurrence.record_type.clone()),
        ("timer", occurrence.timer.clone()),
        ("Record reference", occurrence.record_reference.clone()),
        ("state", occurrence.state.as_str().to_owned()),
        ("timer revision", occurrence.timer_revision.clone()),
        ("executed attempts", occurrence.attempt_count.to_string()),
        ("retry eligible", occurrence.retry_eligible.to_string()),
        ("due at", occurrence.due_at.to_rfc3339()),
        (
            "not after",
            occurrence
                .not_after
                .map(|value| value.to_rfc3339())
                .unwrap_or_else(|| "none".to_owned()),
        ),
        ("created at", occurrence.created_at.to_rfc3339()),
        ("updated at", occurrence.updated_at.to_rfc3339()),
        (
            "completed at",
            occurrence
                .completed_at
                .map(|value| value.to_rfc3339())
                .unwrap_or_else(|| "none".to_owned()),
        ),
        (
            "block kind",
            occurrence
                .block_kind
                .map(|value| value.as_str())
                .unwrap_or("none")
                .to_owned(),
        ),
        (
            "outcome",
            occurrence
                .outcome_code
                .map(|value| value.as_str())
                .unwrap_or("none")
                .to_owned(),
        ),
        ("detail available", occurrence.detail_available.to_string()),
        (
            "detail expires at",
            occurrence
                .detail_expires_at
                .map(|value| value.to_rfc3339())
                .unwrap_or_else(|| "none".to_owned()),
        ),
    ]
}

fn optional(value: Option<&str>) -> String {
    value.unwrap_or("none").to_owned()
}

fn optional_number(value: Option<i64>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

#[cfg(test)]
mod tests {
    use registry_breg::timer_operator::{
        TimerBlockCounts, TimerControlState, TimerEffectiveLimits, TimerOccurrenceCounts,
    };

    use super::*;

    #[test]
    fn status_report_keeps_the_envelope_status_and_a_separate_timer_member() {
        let outcome = TimerOutcome::Status(TimerStatus {
            protocol_version: 1,
            control_state: TimerControlState::Running,
            control_epoch: 3,
            instance_epoch: 4,
            observed_lease_owner_count: 1,
            occurrence_counts: TimerOccurrenceCounts::default(),
            block_counts: TimerBlockCounts::default(),
            stale_revision_count: 0,
            oldest_due_lag_seconds: None,
            limits: TimerEffectiveLimits {
                claim_batch_maximum: 1,
                stale_revision_batch_maximum: 1,
                elapsed_window_batch_maximum: 1,
                maximum_concurrent_attempts: 1,
                operator_list_maximum: 1,
            },
            counts_truncated: false,
        });
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit = write_success(
            "timer status",
            &outcome,
            OutputFormat::Json,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(
            exit,
            ExitCode::SUCCESS,
            "{}",
            String::from_utf8_lossy(&stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["status"], "complete");
        assert_eq!(report["timer"]["controlState"], "running");
        assert_eq!(report["timer"]["controlEpoch"], 3);
    }

    #[test]
    fn runtime_config_refusal_is_actionable_without_dependency_detail() {
        let report = timer_failure("timer status", TimerOperatorError::RuntimeConfigRefused);
        let diagnostic = &report.diagnostics[0];
        assert_eq!(diagnostic.code, "timer.runtime-config.refused");
        assert_eq!(
            diagnostic.artifact,
            DiagnosticArtifact::RuntimeConfiguration
        );
        assert_eq!(diagnostic.path, "runtimeConfig");
        assert_eq!(
            diagnostic.suggested_action,
            SuggestedAction::CorrectRuntimeConfiguration
        );
        assert!(!diagnostic.message.contains("dependency"));
        assert!(!diagnostic.message.contains("secret"));
        assert!(!diagnostic.message.contains("timer status"));
    }

    #[tokio::test]
    async fn invalid_list_request_precedes_unavailable_runtime_config() {
        let unavailable = PathBuf::from("/definitely/unavailable/breg-runtime.yaml");
        let cases = [
            TimerListArgs {
                runtime_config: unavailable.clone(),
                state: None,
                record_type: None,
                timer: None,
                after_cursor: None,
                limit: Some(0),
            },
            TimerListArgs {
                runtime_config: unavailable.clone(),
                state: None,
                record_type: None,
                timer: None,
                after_cursor: None,
                limit: Some(MAXIMUM_TIMER_LIST_LIMIT + 1),
            },
            TimerListArgs {
                runtime_config: unavailable.clone(),
                state: None,
                record_type: Some("Not-A-Local-Id".to_owned()),
                timer: None,
                after_cursor: None,
                limit: None,
            },
            TimerListArgs {
                runtime_config: unavailable,
                state: None,
                record_type: None,
                timer: None,
                after_cursor: Some("not-a-cursor".to_owned()),
                limit: None,
            },
        ];
        for args in cases {
            let error = match TimerCommand::List(args).execute().await {
                Err(error) => error,
                Ok(_) => panic!("invalid list input was not refused"),
            };
            assert_eq!(error, TimerOperatorError::OperationRefused);
        }
    }
}
