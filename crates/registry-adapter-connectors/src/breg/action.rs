// SPDX-License-Identifier: Apache-2.0
//! The BReg immediate Action family (`breg.action.invoke`).
//!
//! The prepared form carries the client's own inert `BRegPreparedAction`
//! evidence (the exact invocation bytes and key) plus the original inputs
//! `recover_action` requires. The closed input shape
//! (`breg.action.invoke/v1`): `{"input": { ...action inputs... }}`.
//!
//! # Target conditions
//!
//! The destination derives target-condition keys from an action's
//! reference inputs, and conditions are an explicit read before
//! invocation. `prepare` performs no I/O. For an action without
//! condition keys the prepared form carries the client's inert evidence
//! and every send re-arms the exact request from it. For a guarded
//! action the client publishes no way to prepare condition-less
//! evidence (`BRegActionInvocationRequest::new` refuses `None`
//! conditions outright, so `prepare_action` cannot run before the
//! conditions exist), so the prepared form carries the inputs and every
//! `send` and `recover` gathers the conditions for the same inputs as
//! the operation's one declared preflight (an unkeyed read the client
//! never resends) before the one keyed exchange under the same key:
//! unchanged targets reproduce the identical body, which the destination
//! replays or executes once, and a moved target produces a different
//! body under a spent key, which the destination answers with
//! `idempotency.key-reused` and the connector surfaces as a refusal.
//! Silence is never read as success.
//!
//! # Correlation and observation
//!
//! The send's correlation is the receipt's application identity alone
//! (`<application-id>`) when the receipt named no result record, or
//! `<application-id>/<record-type>/<record-id>` naming the first result
//! record; observation reads that record back. Either form observes: a
//! bare application identity observes as the family's terminal state,
//! because an immediate Action is complete on its receipt.

use std::sync::{Arc, LazyLock};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use registry_breg_client::{
    BRegActionInvocationRequest, BRegActionTargetConditions, BRegActionTargetConditionsRequest,
    BRegIdempotencyKey, BRegPreparedAction,
};

use crate::operation::{
    BodyKind, CommandKey, ConnectorFault, CredentialRequirements, IdempotencyRule, InputSchema,
    MutationBehavior, NativeState, Observable, Operation, OperationDescriptor, PreparedAttempt,
    Product, RecoveryRule, SendOutcome,
};

use super::{classify, completed, fault};

/// An immediate Action holds the target conditions' declared
/// preconditions; an unguarded action carries none.
pub static INVOKE: LazyLock<OperationDescriptor> = LazyLock::new(|| OperationDescriptor {
    name: "breg.action.invoke",
    product: Product::Breg,
    input_schema: InputSchema::ConnectorDefined {
        shape: "breg.action.invoke/v1".to_owned(),
    },
    body_kind: BodyKind::Json,
    mutation: MutationBehavior::Preconditioned,
    credentials: CredentialRequirements {
        credential_kinds: vec!["private-key-jwt".to_owned()],
        requires_task_grant: false,
        requires_operator_authority: false,
    },
    idempotency: IdempotencyRule::CallerKeyed {
        receipt_retention_days: Some(7),
    },
    recovery: RecoveryRule::ExactSameKey,
    completion: "the destination executed the action once and answered with its receipt",
    observable: true,
});

const OPERATION: &str = "breg.action.invoke";

#[derive(Serialize, Deserialize)]
pub(crate) struct InvokeEnvelope {
    pub version: u8,
    pub operation: String,
    pub key: String,
    pub action: String,
    pub action_revision: String,
    pub inputs: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Value>,
}

/// The exact, persistable immediate Action attempt.
pub struct PreparedInvoke {
    envelope: Vec<u8>,
    key: CommandKey,
}

impl PreparedInvoke {
    /// Restore the stored bytes of one invocation attempt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConnectorFault> {
        let envelope = unseal_invocation(bytes, OPERATION)?;
        Ok(Self {
            envelope: bytes.to_vec(),
            key: CommandKey::new(envelope.key).map_err(|_| ConnectorFault::NotPrepared)?,
        })
    }
}

impl std::fmt::Debug for PreparedInvoke {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedInvoke(<redacted>)")
    }
}

impl PreparedAttempt for PreparedInvoke {
    fn as_bytes(&self) -> &[u8] {
        &self.envelope
    }

    fn operation(&self) -> &'static str {
        OPERATION
    }

    fn key(&self) -> &CommandKey {
        &self.key
    }
}

/// The immediate Action invocation over one connected connector.
pub struct ActionInvoke {
    pub(crate) connector: Arc<super::BregConnector>,
}

/// The prepared invocation material shared by the immediate Action and
/// the Proposal start: the original inputs and, when the action carries
/// no condition keys, the client's inert evidence of the exact request.
pub(crate) struct Invocation {
    pub evidence: Option<BRegPreparedAction>,
    pub inputs: Map<String, Value>,
}

/// Prepare the invocation with no I/O. A guarded action's request cannot
/// exist before its conditions, so only the inputs are validated here and
/// the send gathers the conditions.
pub(crate) fn prepare_invocation(
    connector: &super::BregConnector,
    input: &Value,
    key: &CommandKey,
) -> Result<Invocation, ConnectorFault> {
    let inputs: Map<String, Value> = input
        .get("input")
        .and_then(Value::as_object)
        .ok_or(ConnectorFault::InvalidInput)?
        .clone();
    let guarded = !connector
        .action_binding()
        .required_condition_keys()
        .is_empty();
    let evidence = if guarded {
        None
    } else {
        let request =
            BRegActionInvocationRequest::new(connector.action_binding(), inputs.clone(), None)
                .map_err(|_| ConnectorFault::InvalidInput)?;
        Some(
            connector
                .client()
                .prepare_action(
                    connector.action_binding(),
                    &request,
                    &BRegIdempotencyKey::parse(key.as_str())
                        .map_err(|_| ConnectorFault::InvalidInput)?,
                )
                .map_err(|error| match error {
                    registry_breg_client::BaseRegistryClientError::InvalidRequest { .. } => {
                        ConnectorFault::InvalidInput
                    }
                    _ => fault(&error),
                })?,
        )
    };
    Ok(Invocation { evidence, inputs })
}

/// The condition inputs one action's contract requires, drawn from the
/// invocation inputs.
fn condition_inputs(
    connector: &super::BregConnector,
    inputs: &Map<String, Value>,
) -> Result<Map<String, Value>, ConnectorFault> {
    connector
        .action_binding()
        .required_condition_keys()
        .iter()
        .map(|name| inputs.get(name).cloned().map(|value| (name.clone(), value)))
        .collect::<Option<Map<String, Value>>>()
        .ok_or(ConnectorFault::InvalidInput)
}

/// Read the current target conditions for one invocation's inputs. One
/// unkeyed exchange the client never resends.
fn acquire_conditions(
    connector: &super::BregConnector,
    inputs: &Map<String, Value>,
) -> Result<BRegActionTargetConditions, ConnectorFault> {
    let request = BRegActionTargetConditionsRequest::new(
        connector.action_binding(),
        condition_inputs(connector, inputs)?,
    )
    .map_err(|_| ConnectorFault::InvalidInput)?;
    connector
        .block(
            connector
                .client()
                .action_target_conditions(connector.action_binding(), &request),
        )
        .map(|read| read.value)
        .map_err(|error| fault(&error))
}

/// The invocation request one send executes: the saved evidence re-armed
/// when the action carries no conditions, and otherwise the conditions
/// read fresh for the same inputs. A prepared attempt whose action or its
/// revision left the deployment answers
/// [`ConnectorFault::BindingChanged`] and is never sent.
pub(crate) fn invocation_request(
    connector: &super::BregConnector,
    envelope: &InvokeEnvelope,
) -> Result<BRegActionInvocationRequest, ConnectorFault> {
    if envelope.action != connector.action_binding().action_identifier()
        || envelope.action_revision != connector.action_binding().definition_revision()
    {
        return Err(ConnectorFault::BindingChanged);
    }
    let key = BRegIdempotencyKey::parse(&envelope.key).map_err(|_| ConnectorFault::NotPrepared)?;
    let Some(evidence) = &envelope.evidence else {
        let conditions = acquire_conditions(connector, &envelope.inputs)?;
        return BRegActionInvocationRequest::new(
            connector.action_binding(),
            envelope.inputs.clone(),
            Some(&conditions),
        )
        .map_err(|_| ConnectorFault::InvalidInput);
    };
    let prepared = BRegPreparedAction::from_slice(
        &serde_json::to_vec(evidence).map_err(|_| ConnectorFault::NotPrepared)?,
    )
    .map_err(|_| ConnectorFault::NotPrepared)?;
    connector
        .client()
        .recover_action(
            connector.action_binding(),
            &prepared,
            &envelope.inputs,
            &key,
        )
        .map_err(|error| fault(&error))
}

/// Seal the invocation material under this module's envelope shape.
pub(crate) fn seal_invocation(
    operation: &'static str,
    key: &CommandKey,
    action: &str,
    action_revision: &str,
    invocation: &Invocation,
) -> Result<Vec<u8>, ConnectorFault> {
    let envelope = InvokeEnvelope {
        version: 1,
        operation: operation.to_owned(),
        key: key.as_str().to_owned(),
        action: action.to_owned(),
        action_revision: action_revision.to_owned(),
        inputs: invocation.inputs.clone(),
        evidence: invocation
            .evidence
            .as_ref()
            .map(|evidence| {
                serde_json::from_slice(evidence.as_bytes())
                    .map_err(|_| ConnectorFault::InvalidInput)
            })
            .transpose()?,
    };
    serde_json::to_vec(&envelope).map_err(|_| ConnectorFault::InvalidInput)
}

/// The invocation request one send executes: the saved evidence re-armed
/// when it carries the action's conditions, and otherwise the conditions
/// read fresh for the same inputs. A prepared attempt whose action left
/// the deployment answers [`ConnectorFault::BindingChanged`] and is never
/// sent.
/// Open this module's envelope shape, refusing foreign or earlier forms.
pub(crate) fn unseal_invocation(
    bytes: &[u8],
    operation: &'static str,
) -> Result<InvokeEnvelope, ConnectorFault> {
    let envelope: InvokeEnvelope =
        serde_json::from_slice(bytes).map_err(|_| ConnectorFault::NotPrepared)?;
    if envelope.version != 1 || envelope.operation != operation {
        return Err(ConnectorFault::NotPrepared);
    }
    Ok(envelope)
}

impl ActionInvoke {
    fn execute(&self, prepared: &PreparedInvoke) -> Result<SendOutcome, ConnectorFault> {
        let envelope = unseal_invocation(&prepared.envelope, OPERATION)?;
        let key =
            BRegIdempotencyKey::parse(&envelope.key).map_err(|_| ConnectorFault::NotPrepared)?;
        // The exact saved attempt first: its conditions ride its own
        // bytes, so recovery never re-reads them.
        let request = invocation_request(&self.connector, &envelope)?;
        let answer = self.connector.block(self.connector.client().invoke_action(
            self.connector.action_binding(),
            &request,
            &key,
        ));
        match answer {
            Ok(receipt) => {
                let application = receipt.value.application_identifier();
                let correlation = match receipt.value.results().values().next() {
                    Some(result) => format!(
                        "{application}/{}/{}",
                        result.record_type_identifier(),
                        result.record_identifier()
                    ),
                    None => application.to_string(),
                };
                Ok(completed(correlation))
            }
            Err(error) => classify(&error),
        }
    }
}

impl Observable for ActionInvoke {
    fn observe(&self, correlation: &str) -> Result<NativeState, ConnectorFault> {
        let mut parts = correlation.splitn(3, '/');
        let application = parts.next().ok_or(ConnectorFault::InvalidInput)?;
        match (parts.next(), parts.next()) {
            (Some(record_type), Some(record_identifier)) => {
                let reads = self.connector.reads();
                let record = reads.get_record(record_identifier)?;
                Ok(NativeState {
                    state: "present".to_owned(),
                    details: vec![
                        ("application".to_owned(), application.to_owned()),
                        ("recordType".to_owned(), record_type.to_owned()),
                        (
                            "revision".to_owned(),
                            record.value.data.revision_identifier.clone(),
                        ),
                    ],
                })
            }
            (None, _) | (Some(_), None) => Ok(NativeState {
                // An immediate Action is complete on its receipt; a bare
                // application identity observes as that terminal state.
                state: "completed".to_owned(),
                details: vec![("application".to_owned(), application.to_owned())],
            }),
        }
    }
}

impl Operation for ActionInvoke {
    type Prepared = PreparedInvoke;

    fn describe(&self) -> &OperationDescriptor {
        &INVOKE
    }

    fn prepare(&self, input: &Value, key: CommandKey) -> Result<PreparedInvoke, ConnectorFault> {
        if self.connector.action_mode() != registry_breg_client::BRegActionMode::Immediate {
            return Err(ConnectorFault::NotEnabled);
        }
        let invocation = prepare_invocation(&self.connector, input, &key)?;
        let envelope = seal_invocation(
            OPERATION,
            &key,
            self.connector.action_binding().action_identifier(),
            self.connector.action_binding().definition_revision(),
            &invocation,
        )?;
        Ok(PreparedInvoke { envelope, key })
    }

    fn send(&self, prepared: &PreparedInvoke) -> Result<SendOutcome, ConnectorFault> {
        self.execute(prepared)
    }

    fn recover(&self, prepared: &PreparedInvoke) -> Result<SendOutcome, ConnectorFault> {
        self.execute(prepared)
    }
}
