// SPDX-License-Identifier: Apache-2.0

//! The gateway's own tool-call audit.
//!
//! Each tool call leaves two durable records in the keyed segmented log: an
//! attempt, written before any registry call, and an outcome. A record names
//! the citizen and the chat-host client only by keyed pseudonym, the tool, a
//! request identifier, and a closed outcome code. It never carries a field
//! value, a prompt, an argument, or a credential. The registry keeps its own
//! audit of every read and write it performs for the delegated token.

use std::path::PathBuf;

use registry_platform_audit::{AuditChainHasher, AuditError, DurableSegmentedAuditLog};
use serde_json::json;
use uuid::Uuid;

/// The phase of a tool call a record describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Attempt,
    Outcome,
}

impl Phase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Attempt => "attempt",
            Self::Outcome => "outcome",
        }
    }
}

/// One tool-call audit record, holding only value-free facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ToolAudit<'a> {
    pub(crate) request_id: Uuid,
    pub(crate) tool: &'a str,
    /// The citizen's keyed pseudonym, named as BReg's authorization audit
    /// names a principal.
    pub(crate) principal_pseudonym: &'a str,
    /// The chat-host client's keyed pseudonym.
    pub(crate) client_pseudonym: &'a str,
    pub(crate) phase: Phase,
    /// `ok` or a closed tool error code; absent on an attempt.
    pub(crate) outcome: Option<&'a str>,
}

impl ToolAudit<'_> {
    fn to_value(&self) -> serde_json::Value {
        let mut record = json!({
            "event": "breg_mcp.tool_call",
            "phase": self.phase.as_str(),
            "requestId": self.request_id.to_string(),
            "tool": self.tool,
            "principalPseudonym": self.principal_pseudonym,
            "clientPseudonym": self.client_pseudonym,
        });
        if let Some(outcome) = self.outcome {
            record["outcome"] = serde_json::Value::String(outcome.to_owned());
        }
        record
    }
}

/// The durable tool-call audit log.
pub(crate) struct ToolAuditLog {
    log: DurableSegmentedAuditLog,
}

impl ToolAuditLog {
    pub(crate) async fn open(
        path: PathBuf,
        maximum_file_bytes: u64,
        chain_hasher: AuditChainHasher,
    ) -> Result<Self, AuditError> {
        Ok(Self {
            log: DurableSegmentedAuditLog::initialize(path, maximum_file_bytes, chain_hasher)
                .await?,
        })
    }

    /// Append one record and return once it is durable.
    pub(crate) async fn record(&self, record: &ToolAudit<'_>) -> Result<(), AuditError> {
        self.log.append_record(record.to_value()).await.map(|_| ())
    }

    pub(crate) async fn ready(&self) -> bool {
        self.log.ready().await
    }
}

#[cfg(test)]
mod tests {
    use registry_platform_audit::{verify_segmented_audit_chain, AuditProfile};
    use zeroize::Zeroizing;

    use super::*;

    #[tokio::test]
    async fn a_record_is_durable_and_carries_only_value_free_facts() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(vec![3; 32]))
            .expect("profile");
        let log = ToolAuditLog::open(path.clone(), 1024 * 1024, profile.chain_hasher())
            .await
            .expect("log opens");
        assert!(log.ready().await);
        let request_id = Uuid::new_v4();
        log.record(&ToolAudit {
            request_id,
            tool: "start_application",
            principal_pseudonym: "principal-pseudonym",
            client_pseudonym: "client-pseudonym",
            phase: Phase::Outcome,
            outcome: Some("ok"),
        })
        .await
        .expect("record appends");
        let text = std::fs::read_to_string(&path).expect("log reads");
        let line: serde_json::Value =
            serde_json::from_str(text.lines().next().expect("one line")).expect("line is JSON");
        let record = &line["record"];
        let mut keys: Vec<&str> = record
            .as_object()
            .expect("record object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "clientPseudonym",
                "event",
                "outcome",
                "phase",
                "principalPseudonym",
                "requestId",
                "tool"
            ]
        );
        assert_eq!(record["requestId"], request_id.to_string());
        drop(log);
        verify_segmented_audit_chain(&path, &profile.chain_hasher()).expect("chain verifies");
    }
}
