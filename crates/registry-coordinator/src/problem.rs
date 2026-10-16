// SPDX-License-Identifier: Apache-2.0

//! The closed problem vocabulary of Registry Coordinator.
//!
//! Every refusal the HTTP service answers is an RFC 9457 problem document
//! whose `code` is one of these values and whose `type` is that code under
//! [`PROBLEM_TYPE_BASE`], with each `.` read as a path separator. The
//! vocabulary is closed on purpose: a caller can enumerate every problem this
//! product can ever return, and a problem code outside this list is a defect,
//! not a compatibility event. A code joins the list in the same change that
//! first returns it.
//!
//! The runtime raises its own internal error codes, which `coordinatorctl`
//! reports and the service records; [`for_error`] is the one place that turns
//! an internal code into the public problem the service answers with. Several
//! internal spellings collapse into one public code where a caller has nothing
//! different to do about them.
//!
//! `authorization.refused` is deliberately absent: it is an audit reason
//! family used by other Registry Stack products, and audit reasons and problem
//! codes must not be conflated. The authorization refusals callers see here
//! are `authentication.refused` and `operation.not-authorized`.
//!
//! `run.not-visible` answers every run the caller may not see, whether or not
//! the run exists, and whether its workflow lies outside the caller's policy or it
//! belongs to another caller, so the run routes are never an existence
//! oracle. `workflow.not-served` is answered only after the caller's policy has
//! already admitted a start of the named workflow, so it tells a caller nothing
//! about workflows outside its own policy.
//!
//! The `request.*` family carries the request-edge rejections (a route that
//! does not exist, a method the route refuses, a body too large or not JSON)
//! and the bounded-field refusals of the request itself, under this product's
//! own prefix exactly as Casework, Scheduling and Messaging do: no shared
//! platform problem prefix exists in the Registry Stack catalog.
//!
//! `audit.response-unavailable` is the one 503 after which the operation may
//! already have completed; a caller inspects the run before repeating it.

/// The problem type namespace of Registry Coordinator.
pub const PROBLEM_TYPE_BASE: &str = "https://id.registrystack.org/problems/registry-coordinator/";

pub const ADMISSION_HELD_PROBLEM: &str = "admission.held";
pub const ADMISSION_RECOVERY_ONLY_PROBLEM: &str = "admission.recovery-only";
pub const AUDIT_RESPONSE_UNAVAILABLE_PROBLEM: &str = "audit.response-unavailable";
pub const AUTHENTICATION_REFUSED_PROBLEM: &str = "authentication.refused";
pub const BINDING_CONFLICT_PROBLEM: &str = "binding.conflict";
pub const BINDING_LIVE_CONFLICT_PROBLEM: &str = "binding.live-conflict";
pub const DEFINITION_REFUSED_PROBLEM: &str = "definition.refused";
pub const DEPLOYMENT_ACTIVATION_CHANGED_PROBLEM: &str = "deployment.activation-changed";
pub const DEPLOYMENT_REFUSED_PROBLEM: &str = "deployment.refused";
pub const EVALUATION_UNCERTAIN_PROBLEM: &str = "evaluation.uncertain";
pub const EVENT_INVALID_PROBLEM: &str = "event.invalid";
pub const EVENT_SOURCE_UNAVAILABLE_PROBLEM: &str = "event.source-unavailable";
pub const EVENT_TOO_LARGE_PROBLEM: &str = "event.too-large";
pub const EVENT_UNAUTHENTICATED_PROBLEM: &str = "event.unauthenticated";
pub const EXECUTION_HELD_PROBLEM: &str = "execution.held";
pub const WORKFLOW_NOT_SERVED_PROBLEM: &str = "workflow.not-served";
pub const WORKFLOW_REVISION_MISMATCH_PROBLEM: &str = "workflow.revision-mismatch";
pub const IDEMPOTENCY_KEY_INVALID_PROBLEM: &str = "idempotency.key-invalid";
pub const IDEMPOTENCY_KEY_REUSED_PROBLEM: &str = "idempotency.key-reused";
pub const INPUT_INVALID_PROBLEM: &str = "input.invalid";
pub const OPERATION_NOT_AUTHORIZED_PROBLEM: &str = "operation.not-authorized";
pub const RECEIPT_EXPIRED_PROBLEM: &str = "receipt.expired";
pub const RECONCILE_RACED_PROBLEM: &str = "reconcile.raced";
pub const RECONCILE_REFUSED_PROBLEM: &str = "reconcile.refused";
pub const RECONCILE_UNSUPPORTED_PROBLEM: &str = "reconcile.unsupported";
pub const REQUEST_BODY_TOO_LARGE_PROBLEM: &str = "request.body-too-large";
pub const REQUEST_INVALID_PROBLEM: &str = "request.invalid";
pub const REQUEST_LIMIT_OUT_OF_RANGE_PROBLEM: &str = "request.limit-out-of-range";
pub const REQUEST_METHOD_NOT_ALLOWED_PROBLEM: &str = "request.method-not-allowed";
pub const REQUEST_NOT_FOUND_PROBLEM: &str = "request.not-found";
pub const REQUEST_REASON_INVALID_PROBLEM: &str = "request.reason-invalid";
pub const REQUEST_RETENTION_INVALID_PROBLEM: &str = "request.retention-invalid";
pub const REQUEST_UNPROCESSABLE_PROBLEM: &str = "request.unprocessable";
pub const REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM: &str = "request.unsupported-media-type";
pub const RESTORE_HOLD_REQUIRED_PROBLEM: &str = "restore.hold-required";
pub const RESTORE_LEASE_INCOMPATIBLE_PROBLEM: &str = "restore.lease-incompatible";
pub const RESTORE_REVIEW_REQUIRED_PROBLEM: &str = "restore.review-required";
pub const RESTORE_UNRESOLVED_PROBLEM: &str = "restore.unresolved";
pub const RETRY_REFUSED_PROBLEM: &str = "retry.refused";
pub const RUN_DEFINITION_INCOMPATIBLE_PROBLEM: &str = "run.definition-incompatible";
pub const RUN_NOT_VISIBLE_PROBLEM: &str = "run.not-visible";
pub const RUN_PAYLOAD_ERASED_PROBLEM: &str = "run.payload-erased";
pub const RUNTIME_FAILURE_PROBLEM: &str = "runtime.failure";
pub const SERVICE_UNAVAILABLE_PROBLEM: &str = "service.unavailable";

/// Every problem code Registry Coordinator can return, in code-string order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProblemCode {
    AdmissionHeld,
    AdmissionRecoveryOnly,
    AuditResponseUnavailable,
    AuthenticationRefused,
    BindingConflict,
    BindingLiveConflict,
    DefinitionRefused,
    DeploymentActivationChanged,
    DeploymentRefused,
    EvaluationUncertain,
    EventInvalid,
    EventSourceUnavailable,
    EventTooLarge,
    EventUnauthenticated,
    ExecutionHeld,
    IdempotencyKeyInvalid,
    IdempotencyKeyReused,
    InputInvalid,
    OperationNotAuthorized,
    ReceiptExpired,
    ReconcileRaced,
    ReconcileRefused,
    ReconcileUnsupported,
    RequestBodyTooLarge,
    RequestInvalid,
    RequestLimitOutOfRange,
    RequestMethodNotAllowed,
    RequestNotFound,
    RequestReasonInvalid,
    RequestRetentionInvalid,
    RequestUnprocessable,
    RequestUnsupportedMediaType,
    RestoreHoldRequired,
    RestoreLeaseIncompatible,
    RestoreReviewRequired,
    RestoreUnresolved,
    RetryRefused,
    RunDefinitionIncompatible,
    RunNotVisible,
    RunPayloadErased,
    RuntimeFailure,
    ServiceUnavailable,
    WorkflowNotServed,
    WorkflowRevisionMismatch,
}

impl ProblemCode {
    /// The complete closed vocabulary, in code-string order.
    pub const ALL: &'static [Self] = &[
        Self::AdmissionHeld,
        Self::AdmissionRecoveryOnly,
        Self::AuditResponseUnavailable,
        Self::AuthenticationRefused,
        Self::BindingConflict,
        Self::BindingLiveConflict,
        Self::DefinitionRefused,
        Self::DeploymentActivationChanged,
        Self::DeploymentRefused,
        Self::EvaluationUncertain,
        Self::EventInvalid,
        Self::EventSourceUnavailable,
        Self::EventTooLarge,
        Self::EventUnauthenticated,
        Self::ExecutionHeld,
        Self::IdempotencyKeyInvalid,
        Self::IdempotencyKeyReused,
        Self::InputInvalid,
        Self::OperationNotAuthorized,
        Self::ReceiptExpired,
        Self::ReconcileRaced,
        Self::ReconcileRefused,
        Self::ReconcileUnsupported,
        Self::RequestBodyTooLarge,
        Self::RequestInvalid,
        Self::RequestLimitOutOfRange,
        Self::RequestMethodNotAllowed,
        Self::RequestNotFound,
        Self::RequestReasonInvalid,
        Self::RequestRetentionInvalid,
        Self::RequestUnprocessable,
        Self::RequestUnsupportedMediaType,
        Self::RestoreHoldRequired,
        Self::RestoreLeaseIncompatible,
        Self::RestoreReviewRequired,
        Self::RestoreUnresolved,
        Self::RetryRefused,
        Self::RunDefinitionIncompatible,
        Self::RunNotVisible,
        Self::RunPayloadErased,
        Self::RuntimeFailure,
        Self::ServiceUnavailable,
        Self::WorkflowNotServed,
        Self::WorkflowRevisionMismatch,
    ];

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AdmissionHeld => ADMISSION_HELD_PROBLEM,
            Self::AdmissionRecoveryOnly => ADMISSION_RECOVERY_ONLY_PROBLEM,
            Self::AuditResponseUnavailable => AUDIT_RESPONSE_UNAVAILABLE_PROBLEM,
            Self::AuthenticationRefused => AUTHENTICATION_REFUSED_PROBLEM,
            Self::BindingConflict => BINDING_CONFLICT_PROBLEM,
            Self::BindingLiveConflict => BINDING_LIVE_CONFLICT_PROBLEM,
            Self::DefinitionRefused => DEFINITION_REFUSED_PROBLEM,
            Self::DeploymentActivationChanged => DEPLOYMENT_ACTIVATION_CHANGED_PROBLEM,
            Self::DeploymentRefused => DEPLOYMENT_REFUSED_PROBLEM,
            Self::EvaluationUncertain => EVALUATION_UNCERTAIN_PROBLEM,
            Self::EventInvalid => EVENT_INVALID_PROBLEM,
            Self::EventSourceUnavailable => EVENT_SOURCE_UNAVAILABLE_PROBLEM,
            Self::EventTooLarge => EVENT_TOO_LARGE_PROBLEM,
            Self::EventUnauthenticated => EVENT_UNAUTHENTICATED_PROBLEM,
            Self::ExecutionHeld => EXECUTION_HELD_PROBLEM,
            Self::WorkflowNotServed => WORKFLOW_NOT_SERVED_PROBLEM,
            Self::WorkflowRevisionMismatch => WORKFLOW_REVISION_MISMATCH_PROBLEM,
            Self::IdempotencyKeyInvalid => IDEMPOTENCY_KEY_INVALID_PROBLEM,
            Self::IdempotencyKeyReused => IDEMPOTENCY_KEY_REUSED_PROBLEM,
            Self::InputInvalid => INPUT_INVALID_PROBLEM,
            Self::OperationNotAuthorized => OPERATION_NOT_AUTHORIZED_PROBLEM,
            Self::ReceiptExpired => RECEIPT_EXPIRED_PROBLEM,
            Self::ReconcileRaced => RECONCILE_RACED_PROBLEM,
            Self::ReconcileRefused => RECONCILE_REFUSED_PROBLEM,
            Self::ReconcileUnsupported => RECONCILE_UNSUPPORTED_PROBLEM,
            Self::RequestBodyTooLarge => REQUEST_BODY_TOO_LARGE_PROBLEM,
            Self::RequestInvalid => REQUEST_INVALID_PROBLEM,
            Self::RequestLimitOutOfRange => REQUEST_LIMIT_OUT_OF_RANGE_PROBLEM,
            Self::RequestMethodNotAllowed => REQUEST_METHOD_NOT_ALLOWED_PROBLEM,
            Self::RequestNotFound => REQUEST_NOT_FOUND_PROBLEM,
            Self::RequestReasonInvalid => REQUEST_REASON_INVALID_PROBLEM,
            Self::RequestRetentionInvalid => REQUEST_RETENTION_INVALID_PROBLEM,
            Self::RequestUnprocessable => REQUEST_UNPROCESSABLE_PROBLEM,
            Self::RequestUnsupportedMediaType => REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM,
            Self::RestoreHoldRequired => RESTORE_HOLD_REQUIRED_PROBLEM,
            Self::RestoreLeaseIncompatible => RESTORE_LEASE_INCOMPATIBLE_PROBLEM,
            Self::RestoreReviewRequired => RESTORE_REVIEW_REQUIRED_PROBLEM,
            Self::RestoreUnresolved => RESTORE_UNRESOLVED_PROBLEM,
            Self::RetryRefused => RETRY_REFUSED_PROBLEM,
            Self::RunDefinitionIncompatible => RUN_DEFINITION_INCOMPATIBLE_PROBLEM,
            Self::RunNotVisible => RUN_NOT_VISIBLE_PROBLEM,
            Self::RunPayloadErased => RUN_PAYLOAD_ERASED_PROBLEM,
            Self::RuntimeFailure => RUNTIME_FAILURE_PROBLEM,
            Self::ServiceUnavailable => SERVICE_UNAVAILABLE_PROBLEM,
        }
    }

    /// Resolve a code string back to its variant, or `None` for any string
    /// outside the closed vocabulary.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.code() == code)
    }

    /// The HTTP status this problem answers with, pinned beside the
    /// vocabulary so the runtime emits one status per code.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::EventInvalid
            | Self::IdempotencyKeyInvalid
            | Self::InputInvalid
            | Self::RequestInvalid
            | Self::RequestLimitOutOfRange
            | Self::RequestReasonInvalid
            | Self::RequestRetentionInvalid => 400,
            Self::AuthenticationRefused | Self::EventUnauthenticated => 401,
            Self::OperationNotAuthorized => 403,
            Self::WorkflowNotServed | Self::RequestNotFound | Self::RunNotVisible => 404,
            Self::RequestMethodNotAllowed => 405,
            Self::AdmissionHeld
            | Self::AdmissionRecoveryOnly
            | Self::BindingConflict
            | Self::BindingLiveConflict
            | Self::DefinitionRefused
            | Self::DeploymentActivationChanged
            | Self::DeploymentRefused
            | Self::EvaluationUncertain
            | Self::ExecutionHeld
            | Self::WorkflowRevisionMismatch
            | Self::IdempotencyKeyReused
            | Self::ReceiptExpired
            | Self::ReconcileRaced
            | Self::ReconcileRefused
            | Self::ReconcileUnsupported
            | Self::RestoreHoldRequired
            | Self::RestoreLeaseIncompatible
            | Self::RestoreReviewRequired
            | Self::RestoreUnresolved
            | Self::RetryRefused
            | Self::RunDefinitionIncompatible
            | Self::RunPayloadErased => 409,
            Self::EventTooLarge | Self::RequestBodyTooLarge => 413,
            Self::RequestUnsupportedMediaType => 415,
            Self::RequestUnprocessable => 422,
            Self::RuntimeFailure => 500,
            Self::AuditResponseUnavailable
            | Self::ServiceUnavailable
            | Self::EventSourceUnavailable => 503,
        }
    }

    /// The fixed, value-free problem title. Titles and details carry no
    /// identifiers, workflow inputs, tokens or run data.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::AdmissionHeld => "Admissions held",
            Self::AdmissionRecoveryOnly => "Service admits no runs",
            Self::AuditResponseUnavailable => "Audited result unavailable",
            Self::AuthenticationRefused => "Authentication refused",
            Self::BindingConflict => "Connection settings changed",
            Self::BindingLiveConflict => "Live connection settings changed",
            Self::DefinitionRefused => "Workflow definition refused",
            Self::DeploymentActivationChanged => "Active packages changed",
            Self::DeploymentRefused => "Deployment not serving",
            Self::EvaluationUncertain => "Evaluation outcome uncertain",
            Self::EventInvalid => "Event contract refused",
            Self::EventSourceUnavailable => "Event source unavailable",
            Self::EventTooLarge => "Event too large",
            Self::EventUnauthenticated => "Event authentication refused",
            Self::ExecutionHeld => "Execution held",
            Self::WorkflowNotServed => "Workflow not served",
            Self::WorkflowRevisionMismatch => "Workflow revision mismatch",
            Self::IdempotencyKeyInvalid => "Idempotency key invalid",
            Self::IdempotencyKeyReused => "Idempotency key reused",
            Self::InputInvalid => "Start input invalid",
            Self::OperationNotAuthorized => "Operation not authorized",
            Self::ReceiptExpired => "Original receipt expired",
            Self::ReconcileRaced => "Run changed during reconciliation",
            Self::ReconcileRefused => "Reconciliation refused",
            Self::ReconcileUnsupported => "Reconciliation unsupported",
            Self::RequestBodyTooLarge => "Payload too large",
            Self::RequestInvalid => "Request invalid",
            Self::RequestLimitOutOfRange => "List limit out of range",
            Self::RequestMethodNotAllowed => "Method not allowed",
            Self::RequestNotFound => "Route not found",
            Self::RequestReasonInvalid => "Reason invalid",
            Self::RequestRetentionInvalid => "Retention request invalid",
            Self::RequestUnprocessable => "Request unprocessable",
            Self::RequestUnsupportedMediaType => "Unsupported media type",
            Self::RestoreHoldRequired => "Restore hold required",
            Self::RestoreLeaseIncompatible => "Held work incompatible",
            Self::RestoreReviewRequired => "Recovery review incomplete",
            Self::RestoreUnresolved => "Held work unresolved",
            Self::RetryRefused => "Retry refused",
            Self::RunDefinitionIncompatible => "Run definition unsupported",
            Self::RunNotVisible => "Run not visible",
            Self::RunPayloadErased => "Run payloads erased",
            Self::RuntimeFailure => "Coordinator runtime failure",
            Self::ServiceUnavailable => "Coordinator service unavailable",
        }
    }

    /// The fixed remediation sentence, value-free like the title.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::AdmissionHeld => {
                "Starts stay held after a restore until an operator releases the admission hold."
            }
            Self::AdmissionRecoveryOnly => {
                "This instance runs in recovery-only mode and admits no runs. Send starts to the ordinary service."
            }
            Self::AuditResponseUnavailable => {
                "The operation may have completed, but its audited result could not be released. Inspect the run before repeating the operation."
            }
            Self::AuthenticationRefused => {
                "The bearer credential is missing, invalid, or expired."
            }
            Self::BindingConflict => {
                "The run's original connection settings differ from this service's runtime configuration."
            }
            Self::BindingLiveConflict => {
                "Connection settings that runs in progress use differ from this service's runtime configuration."
            }
            Self::DefinitionRefused => {
                "The workflow's workflow definition, one of its mappings or one of its functions refused the request."
            }
            Self::DeploymentActivationChanged => {
                "An apply changed the active packages after this service started. Restart it with the runtime file that apply used."
            }
            Self::DeploymentRefused => {
                "The deployment's activation, runtime configuration or state key custody check failed."
            }
            Self::EvaluationUncertain => {
                "An evaluation may have completed at its provider, so the run is never evaluated again."
            }
            Self::EventInvalid => "The signed event must satisfy the accepted canonical envelope and typed event contract.",
            Self::EventSourceUnavailable => "Restore the configured event source signing key and its enabled secret provider before retrying delivery.",
            Self::EventTooLarge => "The signed event exceeds the event value profile: 131072 canonical bytes, 32 levels of nesting, 4096 values, 256 items per array, 256 members per object, and 16384 bytes per string. Have the producer project fewer or smaller fields into the event.",
            Self::EventUnauthenticated => "Send a fresh signed delivery from the exact configured source to its accepted trigger.",
            Self::ExecutionHeld => {
                "Execution is under restore hold until an operator releases it."
            }
            Self::WorkflowNotServed => "This deployment does not serve the named workflow.",
            Self::WorkflowRevisionMismatch => {
                "The expected workflow revision differs from the active revision or the original admission."
            }
            Self::IdempotencyKeyInvalid => {
                "Supply an Idempotency-Key header of 1 to 256 bytes."
            }
            Self::IdempotencyKeyReused => {
                "This idempotency key already started a run with different input."
            }
            Self::InputInvalid => {
                "The start input does not satisfy the workflow's declared input schema and value bounds."
            }
            Self::OperationNotAuthorized => {
                "The caller's policy does not allow this operation."
            }
            Self::ReceiptExpired => {
                "The original command's receipt can no longer be recovered. This is not evidence that the command was not sent."
            }
            Self::ReconcileRaced => {
                "The run's progress changed while it was being reconciled. Inspect it again."
            }
            Self::ReconcileRefused => {
                "Reconcile applies only to a held mutation with a prepared command, its original binding and no active lease."
            }
            Self::ReconcileUnsupported => {
                "The held operation has no original-result lookup."
            }
            Self::RequestBodyTooLarge => {
                "The request body exceeds the accepted size: 65536 bytes for a JSON request, or 1048576 bytes for a signed event delivery."
            }
            Self::RequestInvalid => "The request could not be read as a Coordinator request.",
            Self::RequestLimitOutOfRange => "The list limit must be between 1 and 100.",
            Self::RequestMethodNotAllowed => "The route exists but not for this method.",
            Self::RequestNotFound => "The requested route does not exist.",
            Self::RequestReasonInvalid => {
                "The reason or recovery reference must be a bounded reference without personal data or control characters."
            }
            Self::RequestRetentionInvalid => {
                "The retention cutoff must be in the past and the limit between 1 and 100."
            }
            Self::RequestUnprocessable => "The request body could not be processed.",
            Self::RequestUnsupportedMediaType => "The request body is not JSON.",
            Self::RestoreHoldRequired => {
                "This recovery action requires execution to be under restore hold."
            }
            Self::RestoreLeaseIncompatible => {
                "Held work no longer matches its protected definition or prepared command."
            }
            Self::RestoreReviewRequired => {
                "Execution history must be complete and the prior deployment fenced before recovery is reviewed."
            }
            Self::RestoreUnresolved => {
                "Held work remains unresolved, so the restore hold cannot be released."
            }
            Self::RetryRefused => {
                "Retry-same applies only to held work before its original deadline."
            }
            Self::RunDefinitionIncompatible => {
                "This service's Coordinator version cannot interpret the run's pinned definition."
            }
            Self::RunNotVisible => "No run with this identifier is visible to the caller.",
            Self::RunPayloadErased => {
                "Retention erased this run's payloads, so it can no longer be retried or reconciled."
            }
            Self::RuntimeFailure => "Coordinator could not complete the request.",
            Self::ServiceUnavailable => {
                "A dependency of the Coordinator, such as its database, audit stream or token verifier, is unavailable. Try again after the service recovers."
            }
        }
    }
}

/// Expand a dotted problem code into its full problem type URI.
#[must_use]
pub fn type_uri(code: &str) -> String {
    format!("{PROBLEM_TYPE_BASE}{}", code.replace('.', "/"))
}

/// The public problem the HTTP service answers for an internal error code,
/// or `None` for a code the service never answers with. The service treats
/// `None` as a defect and answers `runtime.failure`; a unit test holds every
/// error code raised in this crate either to a problem here or to the list of
/// codes raised only by startup, worker and command-line paths.
pub(crate) fn for_error(code: &str) -> Option<ProblemCode> {
    Some(match code {
        "access.unauthenticated" => ProblemCode::AuthenticationRefused,
        "access.denied" => ProblemCode::OperationNotAuthorized,
        "access.unavailable"
        | "store-unavailable"
        | "protected-state-unavailable"
        | "audit-unavailable" => ProblemCode::ServiceUnavailable,
        "audit-response-unavailable" => ProblemCode::AuditResponseUnavailable,
        "request.invalid" | "admission-invalid" => ProblemCode::RequestInvalid,
        "request.body-too-large" => ProblemCode::RequestBodyTooLarge,
        "request.content-type-invalid" => ProblemCode::RequestUnsupportedMediaType,
        "list-limit-invalid" => ProblemCode::RequestLimitOutOfRange,
        "event-invalid" => ProblemCode::EventInvalid,
        "event-source-unavailable" => ProblemCode::EventSourceUnavailable,
        "event-too-large" => ProblemCode::EventTooLarge,
        "event-unauthenticated" => ProblemCode::EventUnauthenticated,
        "reason-invalid" => ProblemCode::RequestReasonInvalid,
        "retention-invalid" => ProblemCode::RequestRetentionInvalid,
        "run-absent" => ProblemCode::RunNotVisible,
        "workflow-absent" => ProblemCode::WorkflowNotServed,
        "input-invalid" | "definition.input" => ProblemCode::InputInvalid,
        "start-key-invalid" => ProblemCode::IdempotencyKeyInvalid,
        "start-conflict" => ProblemCode::IdempotencyKeyReused,
        "workflow-revision-mismatch" => ProblemCode::WorkflowRevisionMismatch,
        "recovery-only" => ProblemCode::AdmissionRecoveryOnly,
        "restore-admissions-held" => ProblemCode::AdmissionHeld,
        "restore-hold" => ProblemCode::ExecutionHeld,
        "restore-hold-required" => ProblemCode::RestoreHoldRequired,
        "restore-lease-incompatible" => ProblemCode::RestoreLeaseIncompatible,
        "restore-review-required" => ProblemCode::RestoreReviewRequired,
        "restore-unresolved" => ProblemCode::RestoreUnresolved,
        "retry-refused" => ProblemCode::RetryRefused,
        "definition-incompatible" => ProblemCode::RunDefinitionIncompatible,
        "receipt-expired" => ProblemCode::ReceiptExpired,
        "evaluation-uncertain" => ProblemCode::EvaluationUncertain,
        "payload-erased" => ProblemCode::RunPayloadErased,
        "binding-conflict" | "workflow-binding" => ProblemCode::BindingConflict,
        "live-binding-conflict" => ProblemCode::BindingLiveConflict,
        "reconcile-refused" | "definition-invalid" => ProblemCode::ReconcileRefused,
        "reconciliation-unavailable" => ProblemCode::ReconcileUnsupported,
        "reconcile-raced" => ProblemCode::ReconcileRaced,
        "activation-changed" => ProblemCode::DeploymentActivationChanged,
        "deployment.refused"
        | "state-key-custody"
        | "coordinator.deployment.configuration"
        | "coordinator.runtime-config.refused" => ProblemCode::DeploymentRefused,
        "status-unavailable" | "run-state-invalid" | "list-workflow-invalid" => {
            ProblemCode::RuntimeFailure
        }
        code if code.starts_with("definition.")
            || code.starts_with("mapping.")
            || code.starts_with("function.") =>
        {
            ProblemCode::DefinitionRefused
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, fs, path::Path};

    /// Error codes this crate raises only while starting the service, in the
    /// worker, or in `coordinatorctl`. None of them reaches an HTTP answer.
    const UNSERVED: &[&str] = &[
        "access.configuration",
        "adapter.configuration",
        "coordinator.access.configuration",
        "coordinator.cli.usage",
        "coordinator.command.usage",
        "coordinator.decision.configuration",
        "coordinator.external-http.configuration",
        "coordinator.event.configuration",
        "coordinator.operation.contract-invalid",
        "coordinator.operation.proposal-action",
        "database-identity-invalid",
        "database-invalid",
        "database-tls-required",
        "database-version",
        "deployment-invalid",
        "deployment.workflow-live-runs",
        "deployment.workflow-unlisted",
        "lease-stale",
        "listener-unavailable",
        "namespace-invalid",
        "namespace-occupied",
        "output-unavailable",
        "package.refused",
        "project.init",
        "runtime-config-required",
        "runtime-config-unresolved",
        "scenario.missing",
        "scenario.reply",
        "schema-version",
        "service-invalid",
        "service-required",
        "service-unavailable",
        "signal-unavailable",
        "state-keys-invalid",
        "token-file-required",
        "token-invalid",
        "worker-unavailable",
        "workflow.types-refused",
    ];

    /// Every literal error code this crate's source raises, with the files
    /// that raise it: the first argument of `CoordinatorError::new` anywhere,
    /// and of the code-taking helpers that build a `CoordinatorError` in the
    /// store, definition, mapping and function modules.
    fn raised_codes() -> BTreeMap<String, Vec<String>> {
        fn visit(root: &Path, dir: &Path, found: &mut BTreeMap<String, Vec<String>>) {
            let mut entries: Vec<_> = fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            entries.sort();
            for path in entries {
                if path.is_dir() {
                    visit(root, &path, found);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let file = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                // This module names the needles it scans for.
                if file == "problem.rs" {
                    continue;
                }
                let mut needles = vec!["CoordinatorError::new("];
                if file == "store.rs" || file.starts_with("store/") {
                    needles.push("refused(");
                }
                if file == "definition.rs" {
                    needles.extend(["fail(", "authored("]);
                }
                if file == "mapping_check.rs" {
                    needles.push("authored(");
                }
                if file == "functions.rs" {
                    needles.push("failure(");
                }
                let text = fs::read_to_string(&path).unwrap();
                for needle in needles {
                    for (at, _) in text.match_indices(needle) {
                        let helper = needle != "CoordinatorError::new(";
                        let preceded_by_identifier = text[..at]
                            .chars()
                            .next_back()
                            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
                        if helper && preceded_by_identifier {
                            continue;
                        }
                        let rest = text[at + needle.len()..].trim_start();
                        let Some(literal) = rest.strip_prefix('"') else {
                            continue;
                        };
                        let code = literal.split('"').next().unwrap().to_owned();
                        let files = found.entry(code).or_default();
                        if !files.contains(&file) {
                            files.push(file.clone());
                        }
                    }
                }
            }
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = BTreeMap::new();
        visit(&root, &root, &mut found);
        found
    }

    #[test]
    fn every_raised_error_code_answers_a_problem_or_is_never_served() {
        let raised = raised_codes();
        for code in ["access.unauthenticated", "run-absent", "definition.cycle"] {
            assert!(raised.contains_key(code), "the scan missed {code}");
        }
        for (code, files) in &raised {
            assert!(
                for_error(code).is_some() || UNSERVED.contains(&code.as_str()),
                "{code} (raised in {files:?}) maps to no problem; map it in for_error, or list it in UNSERVED if no HTTP route can reach it"
            );
        }
        for code in UNSERVED {
            assert!(raised.contains_key(*code), "{code} is no longer raised");
            assert_eq!(for_error(code), None, "{code} is listed as never served");
        }
    }

    #[test]
    fn every_problem_is_reachable_from_an_internal_code_or_the_request_edge() {
        let edge = [
            ProblemCode::RequestMethodNotAllowed,
            ProblemCode::RequestNotFound,
            ProblemCode::RequestUnprocessable,
        ];
        let raised = raised_codes();
        for problem in ProblemCode::ALL {
            assert!(
                edge.contains(problem)
                    || raised.keys().any(|code| for_error(code) == Some(*problem)),
                "{} is never answered",
                problem.code()
            );
        }
    }

    #[test]
    fn duplicate_internal_spellings_collapse_into_one_public_code() {
        for (internal, public) in [
            ("access.unavailable", ProblemCode::ServiceUnavailable),
            ("store-unavailable", ProblemCode::ServiceUnavailable),
            (
                "protected-state-unavailable",
                ProblemCode::ServiceUnavailable,
            ),
            ("audit-unavailable", ProblemCode::ServiceUnavailable),
            ("input-invalid", ProblemCode::InputInvalid),
            ("definition.input", ProblemCode::InputInvalid),
            ("binding-conflict", ProblemCode::BindingConflict),
            ("workflow-binding", ProblemCode::BindingConflict),
            ("deployment.refused", ProblemCode::DeploymentRefused),
            ("state-key-custody", ProblemCode::DeploymentRefused),
            ("mapping.branch", ProblemCode::DefinitionRefused),
            ("function.arity", ProblemCode::DefinitionRefused),
        ] {
            assert_eq!(for_error(internal), Some(public), "{internal}");
        }
        assert_eq!(for_error("synthetic-unknown"), None);
    }

    #[test]
    fn the_vocabulary_is_complete_and_closed() {
        assert_eq!(ProblemCode::ALL.len(), 44);
        for code in ProblemCode::ALL {
            assert_eq!(ProblemCode::from_code(code.code()), Some(*code));
        }
        assert_eq!(ProblemCode::from_code("authorization.refused"), None);
        assert_eq!(ProblemCode::from_code("run-absent"), None);
        assert_eq!(ProblemCode::from_code(""), None);
        for (internal, public, status) in [
            ("event-invalid", ProblemCode::EventInvalid, 400),
            (
                "event-unauthenticated",
                ProblemCode::EventUnauthenticated,
                401,
            ),
            (
                "event-source-unavailable",
                ProblemCode::EventSourceUnavailable,
                503,
            ),
            ("event-too-large", ProblemCode::EventTooLarge, 413),
        ] {
            assert_eq!(for_error(internal), Some(public));
            assert_eq!(public.http_status(), status);
        }
    }

    #[test]
    fn codes_are_listed_in_code_string_order() {
        let codes: Vec<&str> = ProblemCode::ALL.iter().map(|code| code.code()).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        assert_eq!(codes, sorted);
    }

    #[test]
    fn codes_are_family_dot_kebab_case() {
        for code in ProblemCode::ALL {
            let (family, name) = code.code().split_once('.').expect("a family and a name");
            for part in [family, name] {
                assert!(!part.is_empty(), "{}", code.code());
                assert!(
                    part.bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'-'),
                    "{}",
                    code.code()
                );
            }
        }
    }

    #[test]
    fn type_uris_expand_dots_into_path_segments() {
        assert_eq!(
            type_uri(RUN_NOT_VISIBLE_PROBLEM),
            "https://id.registrystack.org/problems/registry-coordinator/run/not-visible"
        );
        assert_eq!(
            type_uri(REQUEST_UNSUPPORTED_MEDIA_TYPE_PROBLEM),
            "https://id.registrystack.org/problems/registry-coordinator/request/unsupported-media-type"
        );
    }

    #[test]
    fn every_code_pins_a_status_title_and_detail() {
        let statuses = [400, 401, 403, 404, 405, 409, 410, 413, 415, 422, 500, 503];
        for code in ProblemCode::ALL {
            assert!(
                statuses.contains(&code.http_status()),
                "{}: {}",
                code.code(),
                code.http_status()
            );
            assert!(!code.title().is_empty(), "{}", code.code());
            assert!(!code.detail().is_empty(), "{}", code.code());
        }
    }

    /// The request-edge family pins the sibling products' statuses, so the
    /// runtime's edge and every client agree on what a rejected request
    /// looks like.
    #[test]
    fn the_request_edge_family_pins_the_sibling_statuses() {
        assert_eq!(ProblemCode::RequestInvalid.http_status(), 400);
        assert_eq!(ProblemCode::RequestNotFound.http_status(), 404);
        assert_eq!(ProblemCode::RequestMethodNotAllowed.http_status(), 405);
        assert_eq!(ProblemCode::RequestBodyTooLarge.http_status(), 413);
        assert_eq!(ProblemCode::RequestUnsupportedMediaType.http_status(), 415);
        assert_eq!(ProblemCode::RequestUnprocessable.http_status(), 422);
    }

    /// A run the caller may not see answers 404, not 403, so the run routes
    /// never confirm that another caller's run, or a run in a workflow outside
    /// the caller's policy, exists.
    #[test]
    fn an_invisible_run_answers_not_found() {
        assert_eq!(ProblemCode::RunNotVisible.http_status(), 404);
        assert_eq!(for_error("run-absent"), Some(ProblemCode::RunNotVisible));
        assert_eq!(ProblemCode::AuthenticationRefused.http_status(), 401);
        assert_eq!(ProblemCode::OperationNotAuthorized.http_status(), 403);
        assert_eq!(ProblemCode::ServiceUnavailable.http_status(), 503);
        assert_eq!(ProblemCode::AuditResponseUnavailable.http_status(), 503);
    }
}
