// SPDX-License-Identifier: Apache-2.0
//! The small boundary between durable execution and maintained product clients.

use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::time::Duration;

/// An operation resolved from the reviewed binding catalog. An identifier alone
/// grants no product authority and cannot register an arbitrary HTTP operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operation(&'static str);

/// Recovery distinguishes repeatable calls from evaluations that cannot be repeated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoverySemantics {
    ReadAgain,
    SameCommandAndReceipt,
    SameCommand,
    /// Completion may be billable and nondeterministic. An ambiguous dispatch
    /// stays held; identical request bytes cannot establish a safe resend.
    HoldAfterDispatch,
}

macro_rules! operation_constants {
    ($($name:ident => $id:literal, $metadata:expr, $schema:ident;)+) => {
        #[allow(non_upper_case_globals)]
        impl Operation {
            $(pub const $name: Self = Self($id);)+
        }
    };
}
crate::operations::operation_catalog!(operation_constants);

impl Operation {
    pub fn from_catalog_id(identifier: &str) -> Option<Self> {
        Self::parse(identifier)
    }

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
        self.descriptor().effect == crate::operations::EffectKind::Read
    }

    pub fn is_evaluation(self) -> bool {
        self.descriptor().effect == crate::operations::EffectKind::Evaluation
    }

    /// These calls can complete remotely before a local result is committed.
    pub fn has_dispatch_risk(self) -> bool {
        self.is_mutating() || self.is_evaluation()
    }

    pub fn can_retry_after_unknown(self) -> bool {
        self.recovery() != RecoverySemantics::HoldAfterDispatch
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

/// Prepared operation. Exact requests are persisted before dispatch.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallRequest {
    pub connection: String,
    pub operation: Operation,
    pub input: Value,
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_contract: Option<crate::breg_action::ActionContract>,
}

/// One package-declared business refusal from a validated product response.
///
/// The code is deliberately absent from `Debug`; callers must opt in to reading
/// or serializing it for an authored refusal branch.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(deny_unknown_fields))]
pub struct DeclaredRefusal {
    #[cfg_attr(
        feature = "schema",
        schemars(
            length(min = 1, max = 128),
            regex(pattern = r"^[^\u0000-\u001F\u007F-\u009F]+$")
        )
    )]
    refusal_code: String,
}

impl DeclaredRefusal {
    /// Retain only the same bounded code shape the maintained product client
    /// accepts from its wire contract.
    #[must_use]
    pub fn new(refusal_code: &str) -> Option<Self> {
        (!refusal_code.is_empty()
            && refusal_code.chars().count() <= 128
            && !refusal_code.chars().any(char::is_control))
        .then(|| Self {
            refusal_code: refusal_code.to_owned(),
        })
    }

    #[must_use]
    pub fn refusal_code(&self) -> &str {
        self.refusal_code.as_str()
    }
}

impl std::fmt::Debug for DeclaredRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeclaredRefusal(<undisclosed>)")
    }
}

/// Bounded categories. Never carry a remote error body or credential here.
pub enum CallOutcome {
    Success(Value),
    /// The adapter knows this attempt did not execute remotely. For evaluation,
    /// a possibly dispatched request must return Uncertain instead.
    Retryable {
        code: String,
        /// The product's own pause before another attempt, from a bounded
        /// `Retry-After` its client reported. The retry waits at least this
        /// long, up to the longest automatic retry delay.
        retry_after: Option<Duration>,
    },
    Refused {
        code: String,
    },
    /// A validated business refusal explicitly declared by the called product.
    /// This distinct class is eligible for an authored branch at execution time.
    DeclaredRefusal(DeclaredRefusal),
    Uncertain {
        code: String,
    },
    ReceiptExpired,
}

#[cfg(test)]
mod declared_refusal_tests {
    use super::DeclaredRefusal;
    use serde_json::json;

    #[test]
    fn declared_refusal_is_bounded_serializable_and_redacted() {
        let refusal = DeclaredRefusal::new("eligibility-not-met").unwrap();
        assert_eq!(refusal.refusal_code(), "eligibility-not-met");
        assert_eq!(
            serde_json::to_value(&refusal).unwrap(),
            json!({"refusalCode":"eligibility-not-met"})
        );
        assert_eq!(format!("{refusal:?}"), "DeclaredRefusal(<undisclosed>)");
        assert!(DeclaredRefusal::new("").is_none());
        assert!(DeclaredRefusal::new("line\nbreak").is_none());
        assert!(DeclaredRefusal::new(&"x".repeat(129)).is_none());
        assert!(DeclaredRefusal::new(&"é".repeat(128)).is_some());
    }
}

/// Authenticated observation of one retained accepted call. An observation
/// never dispatches a mutation or reconciles an unknown command.
pub enum CompletionObservation {
    Settled(Value),
    Pending {
        retry_after: Option<Duration>,
    },
    Retryable {
        code: String,
        retry_after: Option<Duration>,
    },
    /// Missing, stale, concealed or invalid evidence needs inspection. It is
    /// neither a business result nor proof that an effect did not happen.
    Hold {
        code: String,
    },
}

impl CompletionObservation {
    pub(crate) fn from_failure(outcome: CallOutcome) -> Self {
        match outcome {
            CallOutcome::Retryable { code, retry_after } => Self::Retryable { code, retry_after },
            CallOutcome::Refused { code } | CallOutcome::Uncertain { code } => Self::Hold { code },
            _ => Self::Hold {
                code: "invalid-response".into(),
            },
        }
    }
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
    /// perform bounded authority reads, but must never dispatch a mutation or
    /// a model evaluation.
    /// The host checks authority/deadlines and persists these bytes before send.
    async fn prepare(&self, _request: &CallRequest) -> Result<Option<Vec<u8>>, CallOutcome> {
        Ok(None)
    }

    /// Execute with the original protected preparation. Operations requiring
    /// prepared evidence override this method and validate it before sending.
    async fn call_prepared(&self, request: &CallRequest, _prepared: Option<&[u8]>) -> CallOutcome {
        self.call(request).await
    }

    /// Execute one dispatch attempt. `final_attempt` is true when no automatic
    /// retry can follow this attempt, so an operation that reports a busy
    /// receiver as retryable may deliver its answer instead. Operations that
    /// do not distinguish the final attempt delegate to `call_prepared`.
    async fn call_attempt(
        &self,
        request: &CallRequest,
        prepared: Option<&[u8]>,
        _final_attempt: bool,
    ) -> CallOutcome {
        self.call_prepared(request, prepared).await
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

    /// Observe a named completion of the exact accepted call. Both arguments
    /// are protected durable values. The host interprets bounded external
    /// reads using the immutable Workflow Function, never an adapter script.
    async fn observe_completion(
        &self,
        _request: &CallRequest,
        _accepted: &Value,
        _completion: &crate::definition::CompletionDefinition,
    ) -> CompletionObservation {
        CompletionObservation::Hold {
            code: "operation-unbound".into(),
        }
    }

    fn observation_interval(
        &self,
        _connection: &str,
        completion: &crate::definition::CompletionDefinition,
    ) -> u32 {
        match completion.kind {
            crate::definition::CompletionKind::BoundedPoll {
                interval_seconds, ..
            } => interval_seconds,
            _ => crate::runtime::DEFAULT_RESULT_CHECK_SECONDS,
        }
    }

    /// Minimum spacing enforced even when authenticated signals arrive. The
    /// aggregate ceiling derives from this spacing, not the fallback poll time.
    fn minimum_observation_interval(
        &self,
        connection: &str,
        completion: &crate::definition::CompletionDefinition,
    ) -> u32 {
        if matches!(
            completion.kind,
            crate::definition::CompletionKind::CaseworkResult {}
        ) {
            crate::store::WAIT_READ_SPACING_SECONDS
        } else {
            self.observation_interval(connection, completion)
        }
    }

    /// The connection whose configured completion credential and recipient
    /// binding both match, compared in constant time. Without exactly one
    /// match the sender is not authenticated.
    fn review_completion(&self, _token: &str, _recipient: &str) -> Option<String> {
        None
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
            operation_contract: None,
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
        for final_attempt in [false, true] {
            assert!(matches!(
                adapters.call_attempt(&request, None, final_attempt).await,
                CallOutcome::Success(Value::Null)
            ));
        }
        assert_eq!(adapters.0.load(Ordering::SeqCst), 3);
    }
}
