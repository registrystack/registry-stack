// SPDX-License-Identifier: Apache-2.0
//! The small boundary between durable execution and maintained product clients.

use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// An operation resolved from the reviewed binding catalog. An identifier alone
/// grants no product authority and cannot register an arbitrary HTTP operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operation(&'static str);

/// Recovery is an explicit same-command send or an authoritative read.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoverySemantics {
    ReadAgain,
    SameCommandAndReceipt,
    SameCommand,
}

#[allow(non_upper_case_globals)]
impl Operation {
    // Preserve the existing call-site names and portable operation spellings.
    pub const ReadRecord: Self = Self("read-record");
    pub const SubmitMessage: Self = Self("submit-message");
    pub const ReadScheduling: Self = Self("read-scheduling");
    pub const ReadAvailability: Self = Self("read-availability");
    pub const CreateAppointment: Self = Self("create-appointment");
    pub const InvokeBregAction: Self = Self("invoke-breg-action");
    pub const ExternalGet: Self = Self("external-get");

    pub fn parse(identifier: &str) -> Option<Self> {
        crate::operations::descriptor(identifier).map(|descriptor| Self(descriptor.id))
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }

    pub fn descriptor(self) -> &'static crate::operations::OperationDescriptor {
        crate::operations::descriptor(self.0).expect("Operation is constructed from the catalog")
    }

    pub fn identity(self) -> crate::operations::OperationIdentity {
        self.descriptor().identity()
    }

    pub fn product(self) -> &'static str {
        self.descriptor().product
    }

    pub fn is_mutating(self) -> bool {
        self.descriptor().effect == crate::operations::EffectKind::Mutation
    }

    pub fn is_read(self) -> bool {
        !self.is_mutating()
    }

    pub fn requires_key(self) -> bool {
        self.descriptor().key_requirement == crate::operations::KeyRequirement::Required
    }

    pub fn requires_preparation(self) -> bool {
        self.descriptor().requires_preparation
    }

    pub fn recovery(self) -> RecoverySemantics {
        self.descriptor().recovery
    }

    pub fn supports_read_receipt(self) -> bool {
        self.descriptor().read_receipt
    }
}

impl Serialize for Operation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

impl<'de> Deserialize<'de> for Operation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let identifier = String::deserialize(deserializer)?;
        Self::parse(&identifier)
            .ok_or_else(|| serde::de::Error::custom("operation is not registered"))
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Operation {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Operation".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let identifiers: Vec<_> = crate::operations::descriptors()
            .iter()
            .map(|descriptor| descriptor.id)
            .collect();
        schemars::json_schema!({ "type": "string", "enum": identifiers })
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

    /// Prepare inert exact-request evidence before dispatch. Preparation may
    /// perform bounded authority reads, but must never perform a mutation.
    /// The host checks authority/deadlines and persists these bytes before send.
    async fn prepare(&self, _request: &CallRequest) -> Result<Option<Vec<u8>>, CallOutcome> {
        Ok(None)
    }

    /// Execute with the original protected preparation. Operations requiring
    /// prepared evidence override this method and validate it before sending.
    async fn call_prepared(&self, request: &CallRequest, _prepared: Option<&[u8]>) -> CallOutcome {
        self.call(request).await
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Calls(AtomicUsize);

    #[async_trait]
    impl AdapterSet for Calls {
        fn binding_digest(&self) -> &str {
            "fixture-binding"
        }

        async fn call(&self, _: &CallRequest) -> CallOutcome {
            self.0.fetch_add(1, Ordering::SeqCst);
            CallOutcome::Success(Value::Null)
        }
    }

    #[tokio::test]
    async fn default_preparation_is_inert_and_execution_delegates() {
        let adapters = Calls(AtomicUsize::new(0));
        let request = CallRequest {
            connection: "notices".into(),
            operation: Operation::SubmitMessage,
            input: Value::Null,
            idempotency_key: Some("fixture-key".into()),
        };
        let Ok(prepared) = adapters.prepare(&request).await else {
            panic!("default preparation must accept an existing adapter")
        };
        assert!(prepared.is_none());
        assert_eq!(adapters.0.load(Ordering::SeqCst), 0);
        assert!(matches!(
            adapters.call_prepared(&request, None).await,
            CallOutcome::Success(Value::Null)
        ));
        assert_eq!(adapters.0.load(Ordering::SeqCst), 1);
    }
}
