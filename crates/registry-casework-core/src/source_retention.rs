use serde::{Deserialize, Serialize};

/// Exact source-owned request selected by an operator for local payload erasure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceRetentionSelector {
    pub source_id: String,
    pub request_kind: String,
    pub request_id: String,
}

/// Count-only preview or report. It deliberately carries no erased content or
/// local item identifiers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceRetentionReport {
    pub selector: SourceRetentionSelector,
    pub applied: bool,
    pub blocked_live_attempts: u64,
    pub items: u64,
    pub drafts: u64,
    pub correction_contexts: u64,
    pub attempt_payloads: u64,
    pub receipt_payloads: u64,
    pub history_details: u64,
    pub event_details: u64,
    pub idempotency_responses: u64,
    pub audit_records: u64,
    pub clock_occurrences: u64,
    pub clock_previews: u64,
}
