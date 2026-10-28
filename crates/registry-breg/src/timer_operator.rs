// SPDX-License-Identifier: Apache-2.0

//! Bounded, value-free operator contracts for native Record timers.

use std::{path::Path, str::FromStr};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use registry_platform_audit::{AuditEntry, AuditProfile, AuditRequest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::audit::RegistryAudit;

pub const DEFAULT_TIMER_LIST_LIMIT: u16 = 50;
/// Fixed upper bound enforced by the CLI before it opens deployment configuration.
pub const MAXIMUM_TIMER_LIST_LIMIT: u16 = 200;
const MAX_TIMER_CURSOR_BYTES: usize = 256;
const MAX_OPERATOR_REFERENCE_BYTES: usize = 512;
const MAX_REASON_BYTES: usize = 1024;
const TIMER_CURSOR_VERSION: u8 = 1;
const TIMER_OPERATOR_AUDIT_SCHEMA: &str = "breg-timer-operator-audit/v1";
const TIMER_OPERATOR_REFERENCE_DOMAIN: &str = "breg-timer-operator-reference-v1";
const TIMER_OPERATOR_REASON_DOMAIN: &str = "breg-timer-operator-reason-v1";
const TIMER_OCCURRENCE_REFERENCE_DOMAIN: &str = "breg-timer-occurrence-v1";

macro_rules! closed_vocabulary {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "kebab-case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }
        }

        impl FromStr for $name {
            type Err = TimerOperatorError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(TimerOperatorError::OperationRefused),
                }
            }
        }
    };
}

closed_vocabulary!(TimerControlState {
    Running => "running",
    Paused => "paused",
    AdoptionHold => "adoption-hold",
});

closed_vocabulary!(TimerOccurrenceState {
    Pending => "pending",
    Leased => "leased",
    Completed => "completed",
    Refused => "refused",
    Blocked => "blocked",
    Cancelled => "cancelled",
    Superseded => "superseded",
    Missed => "missed",
});

closed_vocabulary!(TimerBlockKind {
    Technical => "technical",
    Configuration => "configuration",
});

closed_vocabulary!(TimerOutcomeCode {
    Completed => "completed",
    DeclaredRefusal => "declared-refusal",
    InputRefused => "input-refused",
    EffectConflict => "effect-conflict",
    ExecutionWindowExpired => "execution-window-expired",
    ControlCleared => "control-cleared",
    AnchorTombstoned => "anchor-tombstoned",
    BindingRemoved => "binding-removed",
    Superseded => "superseded",
    AttemptsExhausted => "attempts-exhausted",
});

closed_vocabulary!(TimerTechnicalCode {
    HandlerFailure => "handler-failure",
    FieldEncryptionUnavailable => "field-encryption-unavailable",
    ConcurrencyConflict => "concurrency-conflict",
    CommitUnresolved => "commit-unresolved",
    RuntimeUnavailable => "runtime-unavailable",
});

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TimerOperatorError {
    #[error("the timer runtime configuration path must be absolute")]
    RuntimeConfigPath,
    #[error("the timer runtime configuration was refused")]
    RuntimeConfigRefused,
    #[error("the active timer package was refused")]
    PackageRefused,
    #[error("the timer database is unavailable")]
    DatabaseUnavailable,
    #[error("the timer operation outcome is unresolved")]
    OutcomeUnresolved,
    #[error("the timer operation was refused")]
    OperationRefused,
    #[error("the timer occurrence was not found")]
    OccurrenceNotFound,
    #[error("the timer occurrence is not eligible for a technical retry")]
    RetryIneligible,
    #[error("the timer occurrence changed before the operation")]
    OccurrenceChanged,
    #[error("the timer control epoch changed before the operation")]
    ControlEpochMismatch,
    #[error("another timer operation is in progress")]
    InProgress,
    #[error("the timer audit record is unavailable")]
    AuditUnavailable,
    #[error("the timer protocol version is unsupported")]
    ProtocolUnsupported,
}

impl TimerOperatorError {
    #[must_use]
    pub const fn problem_code(&self) -> &'static str {
        match self {
            Self::RuntimeConfigPath => "timer.runtime-config.path-invalid",
            Self::RuntimeConfigRefused => "timer.runtime-config.refused",
            Self::PackageRefused => "timer.package.refused",
            Self::DatabaseUnavailable => "timer.database.unavailable",
            Self::OutcomeUnresolved => "timer.outcome.unresolved",
            Self::OperationRefused => "timer.operation.refused",
            Self::OccurrenceNotFound => "timer.occurrence.not-found",
            Self::RetryIneligible => "timer.retry.ineligible",
            Self::OccurrenceChanged => "timer.occurrence.changed",
            Self::ControlEpochMismatch => "timer.control.epoch-mismatch",
            Self::InProgress => "timer.in-progress",
            Self::AuditUnavailable => "timer.audit.unavailable",
            Self::ProtocolUnsupported => "timer.protocol.unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerOccurrenceCounts {
    pub pending: u64,
    pub leased: u64,
    pub completed: u64,
    pub refused: u64,
    pub blocked: u64,
    pub cancelled: u64,
    pub superseded: u64,
    pub missed: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerBlockCounts {
    pub technical: u64,
    pub configuration: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerEffectiveLimits {
    pub claim_batch_maximum: u32,
    pub stale_revision_batch_maximum: u32,
    pub elapsed_window_batch_maximum: u32,
    pub maximum_concurrent_attempts: u32,
    pub operator_list_maximum: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerStatus {
    pub protocol_version: u32,
    pub control_state: TimerControlState,
    pub control_epoch: i64,
    pub instance_epoch: i64,
    pub observed_lease_owner_count: u32,
    pub occurrence_counts: TimerOccurrenceCounts,
    pub block_counts: TimerBlockCounts,
    pub stale_revision_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_due_lag_seconds: Option<u64>,
    pub limits: TimerEffectiveLimits,
    pub counts_truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerOccurrencePage {
    pub occurrences: Vec<TimerOccurrenceSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerOccurrenceSummary {
    pub occurrence_id: String,
    pub record_type: String,
    pub timer: String,
    pub record_reference: String,
    pub state: TimerOccurrenceState,
    pub timer_revision: String,
    pub attempt_count: u32,
    pub retry_eligible: bool,
    pub due_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_kind: Option<TimerBlockKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome_code: Option<TimerOutcomeCode>,
    pub detail_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerOccurrenceDetail {
    #[serde(flatten)]
    pub summary: TimerOccurrenceSummary,
    pub action_revision: String,
    pub created_activation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_policy_activation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_activation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_epoch: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_epoch: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_epoch: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_reference: Option<String>,
    pub attempts: Vec<TimerAttemptSummary>,
    pub attempts_truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerAttemptSummary {
    pub attempt: u32,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_kind: Option<TimerBlockKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome_code: Option<TimerOutcomeCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technical_code: Option<TimerTechnicalCode>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerRetryOutcome {
    pub occurrence_id: String,
    pub state: TimerOccurrenceState,
    pub attempt_count: u32,
    pub retry_allowance: u8,
    pub control_epoch: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerControlTransition {
    pub previous_control_epoch: i64,
    pub control_epoch: i64,
    pub state: TimerControlState,
    pub changed: bool,
}

/// Package- and database-bound operator access to the native Record-timer
/// ledger. Construction resolves the protected runtime configuration and
/// admits the exact active package before any occurrence is selected.
pub struct TimerOperatorService {
    store: crate::postgres::TimerOperatorStore,
    audit: RegistryAudit,
    activation_id: String,
    limits: TimerEffectiveLimits,
}

impl TimerOperatorService {
    pub async fn from_runtime_config(path: &Path) -> Result<Self, TimerOperatorError> {
        if !path.is_absolute() {
            return Err(TimerOperatorError::RuntimeConfigPath);
        }
        let config = crate::runtime_config::load_runtime_config(path)
            .map_err(|_| TimerOperatorError::RuntimeConfigRefused)?;
        let package = config
            .load_active_package()
            .map_err(|_| TimerOperatorError::PackageRefused)?;
        let audit = RegistryAudit::open_companion(&config)
            .await
            .map_err(|_| TimerOperatorError::AuditUnavailable)?;
        if !crate::audit::profile_is_keyed(audit.profile()) {
            return Err(TimerOperatorError::AuditUnavailable);
        }
        let pool = config
            .runtime_database_connection_config()
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?
            .build_pool()
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| TimerOperatorError::DatabaseUnavailable)?;
        let startup = crate::startup::prepare_loaded_startup(
            package,
            config.identity().database_id(),
            &mut client,
            config.database().roles().migration(),
            config.database().roles().runtime(),
        )
        .await
        .map_err(|error| match error {
            crate::startup::StartupError::PackageRefused(_)
            | crate::startup::StartupError::PackageEnvelopeRefused(_)
            | crate::startup::StartupError::ActivePackageMismatch => {
                TimerOperatorError::PackageRefused
            }
            _ => TimerOperatorError::DatabaseUnavailable,
        })?;
        let expected = startup.expected_identity().clone();
        let activation_id = expected.activation_id.clone();
        let lock_key = startup.lock_key();
        drop(client);
        let limits = crate::postgres::production_timer_limits();
        let store = crate::postgres::TimerOperatorStore::new(
            pool,
            expected,
            lock_key,
            config.operational_timeouts().record_lock,
            crate::postgres::operator_read_statement_budget(),
            limits,
        )?;
        Ok(Self {
            store,
            audit,
            activation_id,
            limits,
        })
    }

    pub async fn status(&self) -> Result<TimerStatus, TimerOperatorError> {
        self.store.status().await.map(Into::into)
    }

    pub async fn list(
        &self,
        request: TimerListRequest<'_>,
    ) -> Result<TimerOccurrencePage, TimerOperatorError> {
        let query = request.validate(self.limits.operator_list_maximum)?;
        self.store
            .list(&query)
            .await?
            .project(self.audit.profile(), &self.activation_id)
    }

    pub async fn show(
        &self,
        occurrence_id: Uuid,
    ) -> Result<TimerOccurrenceDetail, TimerOperatorError> {
        self.store
            .show(occurrence_id)
            .await?
            .ok_or(TimerOperatorError::OccurrenceNotFound)?
            .project(self.audit.profile(), &self.activation_id)
    }

    pub async fn retry(
        &self,
        request: TimerRetryRequest<'_>,
    ) -> Result<TimerRetryOutcome, TimerOperatorError> {
        let request = request.validate()?;
        let context = TimerOperatorAuditContext::retry(self, &request)?;
        let attempt = context.begin(&self.audit).await?;
        match self.store.retry_technical(&request).await {
            Ok(outcome) => {
                let outcome: TimerRetryOutcome = outcome.into();
                context
                    .finish(
                        attempt,
                        "succeeded",
                        json!({
                            "state": outcome.state.as_str(),
                            "attemptCount": outcome.attempt_count,
                            "retryAllowance": outcome.retry_allowance,
                            "controlEpoch": outcome.control_epoch,
                        }),
                    )
                    .await?;
                Ok(outcome)
            }
            Err(error) => {
                context.finish_error(attempt, &error).await?;
                Err(error)
            }
        }
    }

    pub async fn pause(
        &self,
        request: TimerControlRequest<'_>,
    ) -> Result<TimerControlTransition, TimerOperatorError> {
        self.change_control(TimerControlOperation::Pause, request)
            .await
    }

    pub async fn resume(
        &self,
        request: TimerControlRequest<'_>,
    ) -> Result<TimerControlTransition, TimerOperatorError> {
        self.change_control(TimerControlOperation::Resume, request)
            .await
    }

    async fn change_control(
        &self,
        operation: TimerControlOperation,
        request: TimerControlRequest<'_>,
    ) -> Result<TimerControlTransition, TimerOperatorError> {
        let request = request.validate()?;
        let context = TimerOperatorAuditContext::control(self, operation, &request)?;
        let attempt = context.begin(&self.audit).await?;
        let transition = match operation {
            TimerControlOperation::Pause => self.store.pause(&request).await,
            TimerControlOperation::Resume => self.store.resume(&request).await,
        };
        match transition {
            Ok(transition) => {
                let transition: TimerControlTransition = transition.into();
                context
                    .finish(
                        attempt,
                        "succeeded",
                        json!({
                            "previousControlEpoch": transition.previous_control_epoch,
                            "controlEpoch": transition.control_epoch,
                            "state": transition.state.as_str(),
                            "changed": transition.changed,
                        }),
                    )
                    .await?;
                Ok(transition)
            }
            Err(error) => {
                context.finish_error(attempt, &error).await?;
                Err(error)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawTimerRetryOutcome {
    pub(crate) occurrence_id: Uuid,
    pub(crate) state: TimerOccurrenceState,
    pub(crate) attempt_count: u32,
    pub(crate) retry_allowance: u8,
    pub(crate) control_epoch: i64,
}

impl From<RawTimerRetryOutcome> for TimerRetryOutcome {
    fn from(raw: RawTimerRetryOutcome) -> Self {
        Self {
            occurrence_id: raw.occurrence_id.hyphenated().to_string(),
            state: raw.state,
            attempt_count: raw.attempt_count,
            retry_allowance: raw.retry_allowance,
            control_epoch: raw.control_epoch,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawTimerControlTransition {
    pub(crate) previous_control_epoch: i64,
    pub(crate) control_epoch: i64,
    pub(crate) state: TimerControlState,
    pub(crate) changed: bool,
}

impl From<RawTimerControlTransition> for TimerControlTransition {
    fn from(raw: RawTimerControlTransition) -> Self {
        Self {
            previous_control_epoch: raw.previous_control_epoch,
            control_epoch: raw.control_epoch,
            state: raw.state,
            changed: raw.changed,
        }
    }
}

#[derive(Clone, Copy)]
enum TimerControlOperation {
    Pause,
    Resume,
}

impl TimerControlOperation {
    const fn operation_id(self) -> &'static str {
        match self {
            Self::Pause => "breg.timer.pause",
            Self::Resume => "breg.timer.resume",
        }
    }
}

struct TimerOperatorAuditContext {
    audit_profile: AuditProfile,
    correlation: String,
    operation: &'static str,
    activation_id: String,
    operator_reference: String,
    reason_reference: String,
    occurrence_reference: Option<String>,
    expected_attempt_count: Option<u32>,
    expected_control_epoch: Option<i64>,
}

impl TimerOperatorAuditContext {
    fn retry(
        service: &TimerOperatorService,
        request: &ValidatedTimerRetry,
    ) -> Result<Self, TimerOperatorError> {
        let mut context = Self::new(
            service,
            "breg.timer.retry",
            &request.operator_reference,
            &request.reason,
        )?;
        context.occurrence_reference = Some(context.reference(
            TIMER_OCCURRENCE_REFERENCE_DOMAIN,
            &request.occurrence_id.hyphenated().to_string(),
        )?);
        context.expected_attempt_count = Some(request.expected_attempt_count);
        Ok(context)
    }

    fn control(
        service: &TimerOperatorService,
        operation: TimerControlOperation,
        request: &ValidatedTimerControlChange,
    ) -> Result<Self, TimerOperatorError> {
        let mut context = Self::new(
            service,
            operation.operation_id(),
            &request.operator_reference,
            &request.reason,
        )?;
        context.expected_control_epoch = Some(request.expected_control_epoch);
        Ok(context)
    }

    fn new(
        service: &TimerOperatorService,
        operation: &'static str,
        operator_reference: &str,
        reason: &str,
    ) -> Result<Self, TimerOperatorError> {
        let correlation = Uuid::new_v4().hyphenated().to_string();
        let mut context = Self {
            audit_profile: service.audit.profile().clone(),
            correlation,
            operation,
            activation_id: service.activation_id.clone(),
            operator_reference: String::new(),
            reason_reference: String::new(),
            occurrence_reference: None,
            expected_attempt_count: None,
            expected_control_epoch: None,
        };
        context.operator_reference =
            context.reference(TIMER_OPERATOR_REFERENCE_DOMAIN, operator_reference)?;
        context.reason_reference = context.reference(TIMER_OPERATOR_REASON_DOMAIN, reason)?;
        Ok(context)
    }

    fn reference(&self, domain: &str, value: &str) -> Result<String, TimerOperatorError> {
        // The activation is the stable package scope for every operator
        // reference. Distinct domains keep a repeated free-text value from
        // becoming a cross-field lookup handle.
        self.audit_profile
            .key_hasher()
            .audit_reference_hash(domain, &self.activation_id, value)
            .map_err(|_| TimerOperatorError::AuditUnavailable)
    }

    async fn begin(&self, audit: &RegistryAudit) -> Result<AuditRequest, TimerOperatorError> {
        audit
            .begin(
                AuditEntry::request(
                    TIMER_OPERATOR_AUDIT_SCHEMA,
                    self.correlation.clone(),
                    self.record("request", "started", Value::Null),
                ),
                self.record("response", "unfinished", Value::Null),
            )
            .await
            .map_err(|_| TimerOperatorError::AuditUnavailable)
    }

    async fn finish(
        &self,
        attempt: AuditRequest,
        outcome: &str,
        result: Value,
    ) -> Result<(), TimerOperatorError> {
        attempt
            .finish(self.record("response", outcome, result))
            .await
            .map_err(|_| TimerOperatorError::AuditUnavailable)
    }

    async fn finish_error(
        &self,
        attempt: AuditRequest,
        error: &TimerOperatorError,
    ) -> Result<(), TimerOperatorError> {
        self.finish(
            attempt,
            operator_error_audit_outcome(error),
            json!({ "problemCode": error.problem_code() }),
        )
        .await
    }

    fn record(&self, phase: &str, outcome: &str, result: Value) -> Value {
        let mut record = json!({
            "kind": "recordTimerOperator",
            "phase": phase,
            "outcome": outcome,
            "operationId": self.operation,
            "activationId": self.activation_id,
            "actor": "breg:timer-operator",
            "correlation": self.correlation,
            "operatorReference": self.operator_reference,
            "reasonReference": self.reason_reference,
        });
        if let Some(reference) = &self.occurrence_reference {
            record["occurrenceReference"] = json!(reference);
        }
        if let Some(count) = self.expected_attempt_count {
            record["expectedAttemptCount"] = json!(count);
        }
        if let Some(epoch) = self.expected_control_epoch {
            record["expectedControlEpoch"] = json!(epoch);
        }
        if !result.is_null() {
            record["result"] = result;
        }
        record
    }
}

fn operator_error_audit_outcome(error: &TimerOperatorError) -> &'static str {
    match error {
        TimerOperatorError::OutcomeUnresolved => "unfinished",
        _ => "refused",
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawTimerStatus {
    pub(crate) protocol_version: u32,
    pub(crate) control_state: TimerControlState,
    pub(crate) control_epoch: i64,
    pub(crate) instance_epoch: i64,
    pub(crate) observed_lease_owner_count: u32,
    pub(crate) occurrence_counts: TimerOccurrenceCounts,
    pub(crate) block_counts: TimerBlockCounts,
    pub(crate) stale_revision_count: u64,
    pub(crate) oldest_due_lag_seconds: Option<u64>,
    pub(crate) limits: TimerEffectiveLimits,
    pub(crate) counts_truncated: bool,
}

impl From<RawTimerStatus> for TimerStatus {
    fn from(raw: RawTimerStatus) -> Self {
        Self {
            protocol_version: raw.protocol_version,
            control_state: raw.control_state,
            control_epoch: raw.control_epoch,
            instance_epoch: raw.instance_epoch,
            observed_lease_owner_count: raw.observed_lease_owner_count,
            occurrence_counts: raw.occurrence_counts,
            block_counts: raw.block_counts,
            stale_revision_count: raw.stale_revision_count,
            oldest_due_lag_seconds: raw.oldest_due_lag_seconds,
            limits: raw.limits,
            counts_truncated: raw.counts_truncated,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawTimerOccurrencePage {
    pub(crate) occurrences: Vec<RawTimerOccurrenceSummary>,
    pub(crate) next_cursor: Option<TimerListCursor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawTimerOccurrenceSummary {
    pub(crate) occurrence_id: Uuid,
    pub(crate) record_type: String,
    pub(crate) timer: String,
    pub(crate) record_id: Uuid,
    pub(crate) state: TimerOccurrenceState,
    pub(crate) timer_revision: String,
    pub(crate) attempt_count: u32,
    pub(crate) retry_eligible: bool,
    pub(crate) due_at: DateTime<Utc>,
    pub(crate) not_after: Option<DateTime<Utc>>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
    pub(crate) completed_at: Option<DateTime<Utc>>,
    pub(crate) block_kind: Option<TimerBlockKind>,
    pub(crate) outcome_code: Option<TimerOutcomeCode>,
    pub(crate) detail_available: bool,
    pub(crate) detail_expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawTimerOccurrenceDetail {
    pub(crate) summary: RawTimerOccurrenceSummary,
    pub(crate) action_revision: String,
    pub(crate) created_activation_id: Uuid,
    pub(crate) current_policy_activation_id: Option<Uuid>,
    pub(crate) executed_activation_id: Option<Uuid>,
    pub(crate) control_epoch: Option<i64>,
    pub(crate) instance_epoch: Option<i64>,
    pub(crate) claim_epoch: Option<i64>,
    pub(crate) receipt_correlation: Option<Uuid>,
    pub(crate) attempts: Vec<RawTimerAttemptSummary>,
    pub(crate) attempts_truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawTimerAttemptSummary {
    pub(crate) attempt: u32,
    pub(crate) started_at: DateTime<Utc>,
    pub(crate) finished_at: Option<DateTime<Utc>>,
    pub(crate) block_kind: Option<TimerBlockKind>,
    pub(crate) outcome_code: Option<TimerOutcomeCode>,
    pub(crate) technical_code: Option<TimerTechnicalCode>,
}

impl RawTimerOccurrenceSummary {
    fn project(
        self,
        audit: &AuditProfile,
        activation_id: &str,
    ) -> Result<TimerOccurrenceSummary, TimerOperatorError> {
        let record_reference = audit
            .key_hasher()
            .audit_reference_hash(
                "breg-record-v1",
                activation_id,
                &self.record_id.hyphenated().to_string(),
            )
            .map_err(|_| TimerOperatorError::AuditUnavailable)?;
        Ok(TimerOccurrenceSummary {
            occurrence_id: self.occurrence_id.hyphenated().to_string(),
            record_type: self.record_type,
            timer: self.timer,
            record_reference,
            state: self.state,
            timer_revision: self.timer_revision,
            attempt_count: self.attempt_count,
            retry_eligible: self.retry_eligible,
            due_at: self.due_at,
            not_after: self.not_after,
            created_at: self.created_at,
            updated_at: self.updated_at,
            completed_at: self.completed_at,
            block_kind: self.block_kind,
            outcome_code: self.outcome_code,
            detail_available: self.detail_available,
            detail_expires_at: self.detail_expires_at,
        })
    }
}

impl RawTimerOccurrencePage {
    pub(crate) fn project(
        self,
        audit: &AuditProfile,
        activation_id: &str,
    ) -> Result<TimerOccurrencePage, TimerOperatorError> {
        let occurrences = self
            .occurrences
            .into_iter()
            .map(|occurrence| occurrence.project(audit, activation_id))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = self.next_cursor.map(|cursor| cursor.encode()).transpose()?;
        Ok(TimerOccurrencePage {
            occurrences,
            next_cursor,
        })
    }
}

impl RawTimerOccurrenceDetail {
    pub(crate) fn project(
        self,
        audit: &AuditProfile,
        activation_id: &str,
    ) -> Result<TimerOccurrenceDetail, TimerOperatorError> {
        let receipt_reference = self
            .receipt_correlation
            .map(|receipt| {
                audit.key_hasher().audit_reference_hash(
                    "breg-action-receipt-v1",
                    activation_id,
                    &receipt.hyphenated().to_string(),
                )
            })
            .transpose()
            .map_err(|_| TimerOperatorError::AuditUnavailable)?;
        Ok(TimerOccurrenceDetail {
            summary: self.summary.project(audit, activation_id)?,
            action_revision: self.action_revision,
            created_activation_id: self.created_activation_id.hyphenated().to_string(),
            current_policy_activation_id: self
                .current_policy_activation_id
                .map(|id| id.hyphenated().to_string()),
            executed_activation_id: self
                .executed_activation_id
                .map(|id| id.hyphenated().to_string()),
            control_epoch: self.control_epoch,
            instance_epoch: self.instance_epoch,
            claim_epoch: self.claim_epoch,
            receipt_reference,
            attempts: self
                .attempts
                .into_iter()
                .map(|attempt| TimerAttemptSummary {
                    attempt: attempt.attempt,
                    started_at: attempt.started_at,
                    finished_at: attempt.finished_at,
                    block_kind: attempt.block_kind,
                    outcome_code: attempt.outcome_code,
                    technical_code: attempt.technical_code,
                })
                .collect(),
            attempts_truncated: self.attempts_truncated,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerListRequest<'a> {
    pub state: Option<TimerOccurrenceState>,
    pub record_type: Option<&'a str>,
    pub timer: Option<&'a str>,
    pub after_cursor: Option<&'a str>,
    pub limit: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedTimerListQuery {
    pub(crate) state: Option<TimerOccurrenceState>,
    pub(crate) record_type: Option<String>,
    pub(crate) timer: Option<String>,
    pub(crate) after: Option<TimerListCursor>,
    pub(crate) limit: u16,
}

impl TimerListRequest<'_> {
    pub fn validate(
        &self,
        maximum_limit: u16,
    ) -> Result<ValidatedTimerListQuery, TimerOperatorError> {
        if maximum_limit < DEFAULT_TIMER_LIST_LIMIT {
            return Err(TimerOperatorError::OperationRefused);
        }
        let limit = self.limit.unwrap_or(DEFAULT_TIMER_LIST_LIMIT);
        if limit == 0 || limit > maximum_limit {
            return Err(TimerOperatorError::OperationRefused);
        }
        for value in [self.record_type, self.timer].into_iter().flatten() {
            registry_platform_yaml::LocalId::new(value.to_owned())
                .map_err(|_| TimerOperatorError::OperationRefused)?;
        }
        let after = self.after_cursor.map(TimerListCursor::decode).transpose()?;
        Ok(ValidatedTimerListQuery {
            state: self.state,
            record_type: self.record_type.map(str::to_owned),
            timer: self.timer.map(str::to_owned),
            after,
            limit,
        })
    }
}

pub struct TimerRetryRequest<'a> {
    pub occurrence_id: Uuid,
    pub expected_attempt_count: u32,
    pub operator_reference: &'a str,
    pub reason: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedTimerRetry {
    pub(crate) occurrence_id: Uuid,
    pub(crate) expected_attempt_count: u32,
    pub(crate) operator_reference: String,
    pub(crate) reason: String,
}

impl TimerRetryRequest<'_> {
    pub fn validate(&self) -> Result<ValidatedTimerRetry, TimerOperatorError> {
        if self.expected_attempt_count > i32::MAX as u32 {
            return Err(TimerOperatorError::OperationRefused);
        }
        validate_operator_text(self.operator_reference, MAX_OPERATOR_REFERENCE_BYTES)?;
        validate_operator_text(self.reason, MAX_REASON_BYTES)?;
        Ok(ValidatedTimerRetry {
            occurrence_id: self.occurrence_id,
            expected_attempt_count: self.expected_attempt_count,
            operator_reference: self.operator_reference.to_owned(),
            reason: self.reason.to_owned(),
        })
    }
}

pub struct TimerControlRequest<'a> {
    pub expected_control_epoch: i64,
    pub operator_reference: &'a str,
    pub reason: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedTimerControlChange {
    pub(crate) expected_control_epoch: i64,
    pub(crate) operator_reference: String,
    pub(crate) reason: String,
}

impl TimerControlRequest<'_> {
    pub fn validate(&self) -> Result<ValidatedTimerControlChange, TimerOperatorError> {
        if self.expected_control_epoch < 1 {
            return Err(TimerOperatorError::OperationRefused);
        }
        validate_operator_text(self.operator_reference, MAX_OPERATOR_REFERENCE_BYTES)?;
        validate_operator_text(self.reason, MAX_REASON_BYTES)?;
        Ok(ValidatedTimerControlChange {
            expected_control_epoch: self.expected_control_epoch,
            operator_reference: self.operator_reference.to_owned(),
            reason: self.reason.to_owned(),
        })
    }
}

fn validate_operator_text(value: &str, maximum_bytes: usize) -> Result<(), TimerOperatorError> {
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(TimerOperatorError::OperationRefused);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TimerListCursor {
    version: u8,
    created_at: DateTime<Utc>,
    occurrence_id: Uuid,
}

impl TimerListCursor {
    #[must_use]
    pub fn new(created_at: DateTime<Utc>, occurrence_id: Uuid) -> Self {
        Self {
            version: TIMER_CURSOR_VERSION,
            created_at,
            occurrence_id,
        }
    }

    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    #[must_use]
    pub const fn occurrence_id(&self) -> Uuid {
        self.occurrence_id
    }

    pub fn encode(&self) -> Result<String, TimerOperatorError> {
        if self.version != TIMER_CURSOR_VERSION {
            return Err(TimerOperatorError::OperationRefused);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| TimerOperatorError::OperationRefused)?;
        if bytes.is_empty() || bytes.len() > MAX_TIMER_CURSOR_BYTES {
            return Err(TimerOperatorError::OperationRefused);
        }
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn decode(value: &str) -> Result<Self, TimerOperatorError> {
        if value.is_empty() || value.len() > MAX_TIMER_CURSOR_BYTES * 2 {
            return Err(TimerOperatorError::OperationRefused);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| TimerOperatorError::OperationRefused)?;
        if bytes.is_empty() || bytes.len() > MAX_TIMER_CURSOR_BYTES {
            return Err(TimerOperatorError::OperationRefused);
        }
        let cursor: Self =
            serde_json::from_slice(&bytes).map_err(|_| TimerOperatorError::OperationRefused)?;
        if cursor.version != TIMER_CURSOR_VERSION || cursor.encode()?.as_str() != value {
            return Err(TimerOperatorError::OperationRefused);
        }
        Ok(cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor() -> TimerListCursor {
        TimerListCursor::new(
            DateTime::parse_from_rfc3339("2026-10-28T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
        )
    }

    #[test]
    fn list_validation_is_bounded_and_cursor_is_closed() {
        let cursor = cursor();
        let encoded = cursor.encode().unwrap();
        assert_eq!(TimerListCursor::decode(&encoded).unwrap(), cursor);
        assert!(TimerListCursor::decode("").is_err());
        assert!(TimerListCursor::decode("not-a-cursor").is_err());

        let request = TimerListRequest {
            state: Some(TimerOccurrenceState::Blocked),
            record_type: Some("service"),
            timer: Some("activate"),
            after_cursor: Some(&encoded),
            limit: None,
        };
        let validated = request.validate(100).unwrap();
        assert_eq!(validated.limit, DEFAULT_TIMER_LIST_LIMIT);
        assert_eq!(validated.after, Some(cursor));

        let invalid = TimerListRequest {
            limit: Some(0),
            ..request
        };
        assert!(invalid.validate(100).is_err());
        let invalid = TimerListRequest {
            limit: Some(101),
            ..request
        };
        assert!(invalid.validate(100).is_err());
        let invalid = TimerListRequest {
            record_type: Some("Service"),
            ..request
        };
        assert!(invalid.validate(100).is_err());
    }

    #[test]
    fn retry_and_control_validate_before_dependencies() {
        let occurrence_id = Uuid::new_v4();
        let retry = TimerRetryRequest {
            occurrence_id,
            expected_attempt_count: 0,
            operator_reference: "change-42",
            reason: "retry the transient key-service outage",
        }
        .validate()
        .unwrap();
        assert_eq!(retry.occurrence_id, occurrence_id);
        assert_eq!(retry.expected_attempt_count, 0);
        assert_eq!(retry.operator_reference, "change-42");
        assert_eq!(retry.reason, "retry the transient key-service outage");
        assert!(TimerRetryRequest {
            occurrence_id,
            expected_attempt_count: 0,
            operator_reference: "",
            reason: "reason",
        }
        .validate()
        .is_err());
        assert!(TimerRetryRequest {
            occurrence_id,
            expected_attempt_count: i32::MAX as u32 + 1,
            operator_reference: "change-42",
            reason: "reason",
        }
        .validate()
        .is_err());
        let control = TimerControlRequest {
            expected_control_epoch: 42,
            operator_reference: "change-42",
            reason: "maintenance",
        }
        .validate()
        .unwrap();
        assert_eq!(control.expected_control_epoch, 42);
        assert_eq!(control.operator_reference, "change-42");
        assert_eq!(control.reason, "maintenance");
        assert!(TimerControlRequest {
            expected_control_epoch: 0,
            operator_reference: "change-42",
            reason: "maintenance",
        }
        .validate()
        .is_err());
    }

    #[test]
    fn public_projection_uses_closed_value_free_vocabularies() {
        assert_eq!(TimerControlState::AdoptionHold.as_str(), "adoption-hold");
        assert_eq!(TimerOccurrenceState::Superseded.as_str(), "superseded");
        assert_eq!(TimerBlockKind::Configuration.as_str(), "configuration");
        assert_eq!(
            TimerOutcomeCode::ExecutionWindowExpired.as_str(),
            "execution-window-expired"
        );
        assert_eq!(TimerOutcomeCode::InputRefused.as_str(), "input-refused");
        assert_eq!(TimerOutcomeCode::EffectConflict.as_str(), "effect-conflict");
        assert_eq!(
            TimerTechnicalCode::HandlerFailure.as_str(),
            "handler-failure"
        );
        assert_eq!(
            TimerTechnicalCode::FieldEncryptionUnavailable.as_str(),
            "field-encryption-unavailable"
        );
        assert_eq!(
            TimerTechnicalCode::ConcurrencyConflict.as_str(),
            "concurrency-conflict"
        );
        assert_eq!(
            TimerTechnicalCode::CommitUnresolved.as_str(),
            "commit-unresolved"
        );
        assert_eq!(
            TimerTechnicalCode::RuntimeUnavailable.as_str(),
            "runtime-unavailable"
        );
        assert_eq!(
            TimerTechnicalCode::from_str("future-private-code"),
            Err(TimerOperatorError::OperationRefused)
        );
        assert_eq!(
            TimerOperatorError::OccurrenceNotFound.problem_code(),
            "timer.occurrence.not-found"
        );
    }

    #[test]
    fn unresolved_operator_outcome_is_not_a_definite_refusal() {
        let error = TimerOperatorError::OutcomeUnresolved;
        assert_eq!(error.problem_code(), "timer.outcome.unresolved");
        assert_eq!(operator_error_audit_outcome(&error), "unfinished");
    }

    #[test]
    fn occurrence_projection_keys_record_and_receipt_references() {
        let occurrence_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let record_id = Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap();
        let receipt = Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap();
        let activation = Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap();
        let at = DateTime::parse_from_rfc3339("2026-10-28T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let summary = RawTimerOccurrenceSummary {
            occurrence_id,
            record_type: "service".to_owned(),
            timer: "activate".to_owned(),
            record_id,
            state: TimerOccurrenceState::Blocked,
            timer_revision: format!("sha256:{}", "a".repeat(64)),
            attempt_count: 101,
            retry_eligible: true,
            due_at: at,
            not_after: None,
            created_at: at,
            updated_at: at,
            completed_at: None,
            block_kind: Some(TimerBlockKind::Technical),
            outcome_code: None,
            detail_available: true,
            detail_expires_at: None,
        };
        let projected = RawTimerOccurrenceDetail {
            summary,
            action_revision: format!("sha256:{}", "b".repeat(64)),
            created_activation_id: activation,
            current_policy_activation_id: Some(activation),
            executed_activation_id: None,
            control_epoch: Some(7),
            instance_epoch: Some(3),
            claim_epoch: Some(101),
            receipt_correlation: Some(receipt),
            attempts: vec![RawTimerAttemptSummary {
                attempt: 101,
                started_at: at,
                finished_at: None,
                block_kind: Some(TimerBlockKind::Technical),
                outcome_code: None,
                technical_code: Some(TimerTechnicalCode::HandlerFailure),
            }],
            attempts_truncated: true,
        }
        .project(
            &registry_platform_audit::AuditProfile::unkeyed_dev_only(),
            &activation.hyphenated().to_string(),
        )
        .unwrap();

        assert!(projected.attempts_truncated);
        assert_eq!(projected.summary.attempt_count, 101);
        let rendered = serde_json::to_string(&projected).unwrap();
        assert!(!rendered.contains(&record_id.hyphenated().to_string()));
        assert!(!rendered.contains(&receipt.hyphenated().to_string()));
        assert!(rendered.contains("recordReference"));
        assert!(rendered.contains("receiptReference"));
        assert!(rendered.contains("attemptsTruncated"));
        assert!(rendered.contains("\"technicalCode\":\"handler-failure\""));
    }
}
