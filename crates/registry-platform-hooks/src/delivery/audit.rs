// SPDX-License-Identifier: Apache-2.0

//! The hook-delivery audit vocabulary every product records.
//!
//! The worker hands each product a [`DeliveryAuditRecord`]. The words that
//! record is written with, which combinations of phase, outcome, and
//! disposition are coherent, which entries are requests and which answer
//! them, and how one attempt's entries correlate are the same in every
//! product, so they live here. What each product adds is its schema, its
//! event name (`<product>.hook-delivery`), and the identity fields it keys
//! the entry with.

use registry_platform_audit::AuditEntry;
use serde_json::{Map, Value};

use super::seams::{
    DeliveryAuditDisposition, DeliveryAuditOutcome, DeliveryAuditPhase, DeliveryAuditRecord,
    DeliveryTransitionCode,
};

/// The longest compiled delivery id an audit record names.
pub const MAX_AUDIT_COMPILED_DELIVERY_ID_BYTES: usize = 256;

impl DeliveryAuditPhase {
    /// The audit word for this phase.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attempt => "attempt",
            Self::Terminal => "terminal",
            Self::Replay => "replay",
            Self::Discard => "discard",
        }
    }
}

impl DeliveryAuditOutcome {
    /// The audit word for this outcome. An outcome that repeats a
    /// dead-letter reason is spelled exactly as the stored reason is.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AttemptStarted => "attempt-started",
            Self::Delivered => "delivered",
            Self::HttpNonSuccess => "http-non-success",
            Self::DestinationTimeout => "destination-timeout",
            Self::DestinationResolutionRefused => "destination-resolution-refused",
            Self::DestinationTransportUnavailable => "destination-transport-unavailable",
            Self::DestinationPolicyRefused => "destination-policy-refused",
            Self::DestinationBindingRefused => "destination-binding-refused",
            Self::HandlerBindingRefused => "handler-binding-refused",
            Self::HandlerDeadline => "handler-deadline",
            Self::HandlerResource => "handler-resource",
            Self::HandlerExecution => "handler-execution",
            Self::HandlerSource => "handler-source",
            Self::HandlerUnavailable => "handler-unavailable",
            Self::PayloadRefused => "payload-refused",
            Self::PayloadExpired => "payload-expired",
            Self::WorkerInterrupted => "worker-interrupted",
            Self::ReplayRequested => "replay-requested",
            Self::ReplayCommitted => "replay-committed",
            Self::ReplayRefused => "replay-refused",
            Self::ReplayUnfinished => "replay-unfinished",
            Self::DiscardRequested => "discard-requested",
            Self::DiscardCommitted => "discard-committed",
            Self::DiscardRefused => "discard-refused",
            Self::DiscardUnfinished => "discard-unfinished",
        }
    }
}

impl DeliveryAuditDisposition {
    /// The audit word for where a delivery stands. `retry-pending`,
    /// `dead-lettered`, and `replay-pending` repeat the words the delivery
    /// tables store.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Leased => "leased",
            Self::Delivered => "delivered",
            Self::RetryPending => "retry-pending",
            Self::DeadLettered => "dead-lettered",
            Self::Expired => "expired",
            Self::ReplayPending => "replay-pending",
            Self::DiscardPending => "discard-pending",
            Self::Discarded => "discarded",
            Self::Unknown => "unknown",
        }
    }
}

impl DeliveryTransitionCode {
    /// The value-free operational code for this failed transition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimIdentityRefused => "claim_identity_refused",
            Self::ClaimRecoveryFailed => "claim_recovery_failed",
            Self::ClaimSelectFailed => "claim_select_failed",
            Self::ClaimPolicyRefused => "claim_policy_refused",
            Self::ClaimUpdateFailed => "claim_update_failed",
            Self::ClaimAuditFailed => "claim_audit_failed",
            Self::ClaimCommitFailed => "claim_commit_failed",
        }
    }
}

/// A delivery-audit record whose shape no worker transition produces.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the hook delivery audit record is not a shape the worker records")]
pub struct InvalidDeliveryAudit;

impl DeliveryAuditRecord<'_> {
    /// Whether this record is one the worker can produce: a coherent phase,
    /// outcome, and disposition, an attempt number that fits the phase, a
    /// positive generation, and non-empty bounded identities.
    #[must_use]
    pub fn has_valid_shape(&self) -> bool {
        use DeliveryAuditDisposition as D;
        use DeliveryAuditOutcome as O;
        use DeliveryAuditPhase as P;
        let attempt = self.attempt;
        let combination = match (self.phase, self.outcome, self.disposition) {
            (P::Attempt, O::AttemptStarted, D::Leased) => attempt > 0,
            (P::Terminal, O::Delivered, D::Delivered)
            // A delivered answer whose proposal dead-lettered: the attempt
            // succeeded, and the deterministic proposal refusal is what made
            // the row terminal.
            | (P::Terminal, O::Delivered, D::DeadLettered)
            | (
                P::Terminal,
                O::HttpNonSuccess
                | O::DestinationTimeout
                | O::DestinationResolutionRefused
                | O::DestinationTransportUnavailable
                | O::DestinationPolicyRefused
                | O::DestinationBindingRefused
                | O::HandlerBindingRefused
                | O::HandlerDeadline
                | O::HandlerResource
                | O::HandlerExecution
                | O::HandlerSource
                | O::HandlerUnavailable
                | O::PayloadRefused
                | O::WorkerInterrupted,
                D::RetryPending | D::DeadLettered,
            )
            | (P::Terminal, O::WorkerInterrupted, D::Unknown) => attempt > 0,
            (P::Terminal, O::PayloadExpired, D::Expired) => attempt >= 0,
            (
                P::Replay,
                O::ReplayRequested | O::ReplayCommitted | O::ReplayUnfinished,
                D::ReplayPending,
            )
            | (P::Replay, O::ReplayRefused, D::DeadLettered) => attempt == 0,
            (P::Discard, O::DiscardRequested | O::DiscardRefused, D::DiscardPending)
            | (P::Discard, O::DiscardCommitted, D::Discarded)
            | (P::Discard, O::DiscardUnfinished, D::Unknown) => attempt >= 0,
            _ => false,
        };
        combination
            && self.generation > 0
            && !self.compiled_delivery_id.is_empty()
            && self.compiled_delivery_id.len() <= MAX_AUDIT_COMPILED_DELIVERY_ID_BYTES
            && !self.package_revision.is_empty()
    }

    /// Whether this record is a `request` entry. An attempt's start and an
    /// operator's replay or discard request are requests; the terminal
    /// disposition and the committed, refused, or unfinished reset answer
    /// them under the same correlation.
    #[must_use]
    pub fn is_request(&self) -> bool {
        matches!(
            (self.phase, self.outcome),
            (DeliveryAuditPhase::Attempt, _)
                | (
                    DeliveryAuditPhase::Replay,
                    DeliveryAuditOutcome::ReplayRequested
                )
                | (
                    DeliveryAuditPhase::Discard,
                    DeliveryAuditOutcome::DiscardRequested
                )
        )
    }

    /// The correlation of this record's entry: the product's base for one
    /// attempt, with `.discard` appended for a discard so it never pairs with
    /// the attempt it erases.
    #[must_use]
    pub fn correlation(&self, base: &str) -> String {
        if self.phase == DeliveryAuditPhase::Discard {
            format!("{base}.discard")
        } else {
            base.to_owned()
        }
    }
}

/// Build the audit entry for one delivery transition.
///
/// `fields` are the product's identity fields (how it names the event, the
/// delivery, and the package). This adds `event`, `phase`, `outcome`,
/// `disposition`, `generation`, and `attempt`, files the entry as a request
/// or a response, and correlates it from `correlation_base`.
///
/// # Errors
///
/// [`InvalidDeliveryAudit`] when the record's shape is not one the worker
/// produces.
pub fn hook_audit_entry(
    schema: &str,
    event_name: &str,
    correlation_base: &str,
    mut fields: Map<String, Value>,
    record: &DeliveryAuditRecord<'_>,
) -> Result<AuditEntry, InvalidDeliveryAudit> {
    if !record.has_valid_shape() {
        return Err(InvalidDeliveryAudit);
    }
    fields.insert("event".to_owned(), Value::from(event_name));
    fields.insert("phase".to_owned(), Value::from(record.phase.as_str()));
    fields.insert("outcome".to_owned(), Value::from(record.outcome.as_str()));
    fields.insert(
        "disposition".to_owned(),
        Value::from(record.disposition.as_str()),
    );
    fields.insert("generation".to_owned(), Value::from(record.generation));
    fields.insert("attempt".to_owned(), Value::from(record.attempt));
    let correlation = record.correlation(correlation_base);
    let record_value = Value::Object(fields);
    Ok(if record.is_request() {
        AuditEntry::request(schema, correlation, record_value)
    } else {
        AuditEntry::response(schema, correlation, record_value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::DeliveryFailureReason;
    use uuid::Uuid;

    const OUTCOMES: [DeliveryAuditOutcome; 25] = [
        DeliveryAuditOutcome::AttemptStarted,
        DeliveryAuditOutcome::Delivered,
        DeliveryAuditOutcome::HttpNonSuccess,
        DeliveryAuditOutcome::DestinationTimeout,
        DeliveryAuditOutcome::DestinationResolutionRefused,
        DeliveryAuditOutcome::DestinationTransportUnavailable,
        DeliveryAuditOutcome::DestinationPolicyRefused,
        DeliveryAuditOutcome::DestinationBindingRefused,
        DeliveryAuditOutcome::HandlerBindingRefused,
        DeliveryAuditOutcome::HandlerDeadline,
        DeliveryAuditOutcome::HandlerResource,
        DeliveryAuditOutcome::HandlerExecution,
        DeliveryAuditOutcome::HandlerSource,
        DeliveryAuditOutcome::HandlerUnavailable,
        DeliveryAuditOutcome::PayloadRefused,
        DeliveryAuditOutcome::PayloadExpired,
        DeliveryAuditOutcome::WorkerInterrupted,
        DeliveryAuditOutcome::ReplayRequested,
        DeliveryAuditOutcome::ReplayCommitted,
        DeliveryAuditOutcome::ReplayRefused,
        DeliveryAuditOutcome::ReplayUnfinished,
        DeliveryAuditOutcome::DiscardRequested,
        DeliveryAuditOutcome::DiscardCommitted,
        DeliveryAuditOutcome::DiscardRefused,
        DeliveryAuditOutcome::DiscardUnfinished,
    ];

    fn record(
        phase: DeliveryAuditPhase,
        outcome: DeliveryAuditOutcome,
        disposition: DeliveryAuditDisposition,
        attempt: i16,
    ) -> DeliveryAuditRecord<'static> {
        DeliveryAuditRecord {
            event_id: Uuid::nil(),
            compiled_delivery_id: "events.case.created.hook",
            package_revision: "sha256:package",
            generation: 1,
            attempt,
            phase,
            outcome,
            disposition,
        }
    }

    #[test]
    fn audit_words_are_kebab_case_and_distinct() {
        let mut seen = std::collections::BTreeSet::new();
        for outcome in OUTCOMES {
            let word = outcome.as_str();
            assert!(word
                .bytes()
                .all(|byte| byte == b'-' || byte.is_ascii_lowercase()));
            assert!(seen.insert(word), "{word} repeats");
        }
        assert_eq!(DeliveryAuditPhase::Discard.as_str(), "discard");
        assert_eq!(
            DeliveryAuditDisposition::RetryPending.as_str(),
            "retry-pending"
        );
        assert_eq!(
            DeliveryTransitionCode::ClaimIdentityRefused.as_str(),
            "claim_identity_refused"
        );
    }

    #[test]
    fn dead_letter_outcomes_repeat_the_stored_reason_words() {
        for (outcome, reason) in [
            (
                DeliveryAuditOutcome::HttpNonSuccess,
                DeliveryFailureReason::HttpNonSuccess,
            ),
            (
                DeliveryAuditOutcome::DestinationTimeout,
                DeliveryFailureReason::DestinationTimeout,
            ),
            (
                DeliveryAuditOutcome::DestinationPolicyRefused,
                DeliveryFailureReason::DestinationPolicyRefused,
            ),
            (
                DeliveryAuditOutcome::DestinationBindingRefused,
                DeliveryFailureReason::DestinationBindingRefused,
            ),
            (
                DeliveryAuditOutcome::HandlerBindingRefused,
                DeliveryFailureReason::HandlerBindingRefused,
            ),
            (
                DeliveryAuditOutcome::HandlerDeadline,
                DeliveryFailureReason::HandlerDeadline,
            ),
            (
                DeliveryAuditOutcome::HandlerResource,
                DeliveryFailureReason::HandlerResource,
            ),
            (
                DeliveryAuditOutcome::HandlerExecution,
                DeliveryFailureReason::HandlerExecution,
            ),
            (
                DeliveryAuditOutcome::HandlerSource,
                DeliveryFailureReason::HandlerSource,
            ),
            (
                DeliveryAuditOutcome::HandlerUnavailable,
                DeliveryFailureReason::HandlerUnavailable,
            ),
            (
                DeliveryAuditOutcome::PayloadRefused,
                DeliveryFailureReason::PayloadRefused,
            ),
            (
                DeliveryAuditOutcome::WorkerInterrupted,
                DeliveryFailureReason::WorkerInterrupted,
            ),
        ] {
            assert_eq!(outcome.as_str(), reason.as_str());
        }
    }

    #[test]
    fn shape_check_accepts_only_worker_transitions() {
        use DeliveryAuditDisposition as D;
        use DeliveryAuditOutcome as O;
        use DeliveryAuditPhase as P;
        assert!(record(P::Attempt, O::AttemptStarted, D::Leased, 1).has_valid_shape());
        assert!(!record(P::Attempt, O::AttemptStarted, D::Leased, 0).has_valid_shape());
        assert!(record(P::Terminal, O::Delivered, D::DeadLettered, 2).has_valid_shape());
        assert!(!record(P::Terminal, O::Delivered, D::RetryPending, 2).has_valid_shape());
        assert!(record(P::Terminal, O::PayloadExpired, D::Expired, 0).has_valid_shape());
        assert!(record(P::Replay, O::ReplayRefused, D::DeadLettered, 0).has_valid_shape());
        assert!(!record(P::Replay, O::ReplayRefused, D::DeadLettered, 1).has_valid_shape());
        assert!(record(P::Discard, O::DiscardUnfinished, D::Unknown, 3).has_valid_shape());
        assert!(!record(P::Discard, O::DiscardCommitted, D::Unknown, 3).has_valid_shape());
        let mut zero_generation = record(P::Attempt, O::AttemptStarted, D::Leased, 1);
        zero_generation.generation = 0;
        assert!(!zero_generation.has_valid_shape());
        let long_id = "x".repeat(MAX_AUDIT_COMPILED_DELIVERY_ID_BYTES + 1);
        let mut long = record(P::Attempt, O::AttemptStarted, D::Leased, 1);
        long.compiled_delivery_id = &long_id;
        assert!(!long.has_valid_shape());
    }

    #[test]
    fn entries_pair_requests_with_their_answers() {
        use DeliveryAuditDisposition as D;
        use DeliveryAuditOutcome as O;
        use DeliveryAuditPhase as P;
        let mut fields = Map::new();
        fields.insert("eventReference".to_owned(), Value::from("ref"));
        let attempt = record(P::Attempt, O::AttemptStarted, D::Leased, 1);
        assert!(attempt.is_request());
        let entry = hook_audit_entry(
            "x-hook-audit/v1",
            "x.hook-delivery",
            "base",
            fields,
            &attempt,
        )
        .expect("entry");
        assert_eq!(entry.schema(), "x-hook-audit/v1");
        assert_eq!(entry.correlation(), "base");
        assert_eq!(entry.record()["event"], "x.hook-delivery");
        assert_eq!(entry.record()["phase"], "attempt");
        assert_eq!(entry.record()["eventReference"], "ref");
        let terminal = record(P::Terminal, O::Delivered, D::Delivered, 1);
        assert!(!terminal.is_request());
        let discard = record(P::Discard, O::DiscardRequested, D::DiscardPending, 1);
        assert!(discard.is_request());
        assert_eq!(discard.correlation("base"), "base.discard");
        assert_eq!(
            hook_audit_entry(
                "x-hook-audit/v1",
                "x.hook-delivery",
                "base",
                Map::new(),
                &record(P::Replay, O::ReplayCommitted, D::ReplayPending, 1),
            )
            .unwrap_err(),
            InvalidDeliveryAudit
        );
    }
}
