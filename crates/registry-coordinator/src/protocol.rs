// SPDX-License-Identifier: Apache-2.0
//! The small boundary between durable execution and maintained product clients.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Supported product operations. No arbitrary HTTP escape hatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    ReadRecord,
    SubmitMessage,
    ReadScheduling,
    ReadAvailability,
    CreateAppointment,
}

/// Recovery is an explicit same-command send or an authoritative read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoverySemantics {
    ReadAgain,
    SameCommandAndReceipt,
}

impl Operation {
    pub const fn product(self) -> &'static str {
        match self {
            Self::ReadRecord => "breg",
            Self::SubmitMessage => "messaging",
            Self::ReadScheduling | Self::ReadAvailability | Self::CreateAppointment => "scheduling",
        }
    }

    pub const fn is_mutating(self) -> bool {
        matches!(self, Self::SubmitMessage | Self::CreateAppointment)
    }

    pub const fn is_read(self) -> bool {
        !self.is_mutating()
    }

    pub const fn recovery(self) -> RecoverySemantics {
        if self.is_mutating() {
            RecoverySemantics::SameCommandAndReceipt
        } else {
            RecoverySemantics::ReadAgain
        }
    }
}

/// Read-only recovery cannot manufacture proof of a previous effect.
pub enum ReconciliationOutcome {
    /// The owning product matched the original key, request identity and caller.
    Confirmed(Value),
    /// Observation, refusal, missing evidence or outage cannot settle this command.
    Unresolved { code: String },
}

/// Prepared operation. Mutation requests are persisted before dispatch.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallRequest {
    pub connection: String,
    pub operation: Operation,
    pub input: Value,
    pub idempotency_key: Option<String>,
}

/// Bounded categories. Never carry a remote error body or credential here.
pub enum CallOutcome {
    Success(Value),
    Retryable { code: String },
    Refused { code: String },
    Uncertain { code: String },
    ReceiptExpired,
}

#[async_trait]
pub trait AdapterSet: Send + Sync {
    /// Covers semantic principal, destination, scopes and request interpretation.
    /// Secret bytes and routine credential renewal are not command identity.
    fn binding_digest(&self) -> &str;

    fn binding_digest_for(&self, _workflow: &crate::definition::Workflow) -> String {
        self.binding_digest().to_owned()
    }

    async fn call(&self, request: &CallRequest) -> CallOutcome;

    /// Any `accepted` receipt comes from protected durable state, never operator
    /// text. HTTP adapters look up the exact original command regardless of it.
    /// This method performs reads only, and cannot authorize a new command.
    async fn reconcile(
        &self,
        _request: &CallRequest,
        _accepted: Option<&Value>,
    ) -> ReconciliationOutcome {
        ReconciliationOutcome::Unresolved {
            code: "reconciliation-unavailable".into(),
        }
    }
}
