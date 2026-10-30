// SPDX-License-Identifier: Apache-2.0
//! Reviewed workflow bindings over maintained clients. This catalog owns
//! execution metadata, not product authorization or wire implementation.

use serde::{Deserialize, Serialize};

use crate::protocol::{Operation, RecoverySemantics};

// These are host policy, consumed by Dispatch and by the compiled contract.
// A local Operation alias cannot increase them or claim stronger recovery.
pub(crate) const ATTEMPT_TIMEOUT_SECONDS: u64 = 10;
pub(crate) const MAXIMUM_ATTEMPTS: i16 = 10;
pub(crate) const RETRY_MAXIMUM_DELAY_SECONDS: u64 = 300;
pub(crate) const MAXIMUM_PREPARATION_BYTES: usize = 65_536;
pub(crate) const MINIMUM_OBSERVATION_INTERVAL_SECONDS: u32 = 30;
pub(crate) const MAXIMUM_OBSERVATION_INTERVAL_SECONDS: u32 = 86_400;
pub(crate) const MAXIMUM_HTTP_RESPONSE_BYTES: u64 = 65_536;
pub(crate) const HTTP_REQUEST_TIMEOUT_MILLISECONDS: u64 = 2_000;
pub(crate) const HTTP_CONNECT_TIMEOUT_MILLISECONDS: u64 = 1_000;
pub(crate) const HTTP_MUTATION_RETRIES: u8 = 0;
pub(crate) const EVALUATION_TIMEOUT_MILLISECONDS: u64 = 8_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectKind {
    Read,
    Mutation,
    Evaluation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyRequirement {
    None,
    Required,
}

/// Binding behavior is versioned independently of the workflow. The fields
/// copied into [`OperationIdentity`] must not silently change for an admitted
/// run. `declared_refusal` is an authoring capability outside that identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationDescriptor {
    pub id: &'static str,
    pub version: u32,
    pub product: &'static str,
    pub effect: EffectKind,
    pub key_requirement: KeyRequirement,
    pub requires_preparation: bool,
    pub recovery: RecoverySemantics,
    pub read_receipt: bool,
    /// Whether a call may route a product-declared, no-effect business
    /// refusal through `onDeclaredRefusal`.
    ///
    /// The capability is outside [`OperationIdentity`]. A snapshot carries the
    /// authored edge itself, and restoring it refuses an edge on an operation
    /// that does not declare the capability.
    pub declared_refusal: bool,
}

/// Exact nonsecret binding semantics retained in the immutable snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationIdentity {
    pub id: String,
    pub version: u32,
    pub product: String,
    pub effect: EffectKind,
    pub key_requirement: KeyRequirement,
    pub requires_preparation: bool,
    pub recovery: RecoverySemantics,
    pub read_receipt: bool,
}

impl OperationDescriptor {
    /// The host-owned execution contract, shared by compilation, generated
    /// references and inspection. Product authorization is checked afresh;
    /// this metadata cannot grant it or make an unknown command successful.
    pub fn host_contract(&self) -> serde_json::Value {
        use serde_json::json;
        let mut observation = match self.id {
            id if id == Operation::SubmitReviewRequest.as_str() => json!({
                "name":"result", "profile":"casework-result",
                "acceptedBinding":["requestId","subject","policy","submissionDigest"],
                "authority":"current-review-producer",
                "terminalEvidence":"exact-authorized-review-result",
                "authenticatedWake":true,
                "defaultIntervalSeconds":crate::runtime::DEFAULT_RESULT_CHECK_SECONDS
            }),
            id if id == Operation::ExternalGet.as_str() => json!({
                "profile":"bounded-poll", "specializationRequired":true,
                "acceptedBinding":["saved-command"],
                "authority":"bound-read-only-connection",
                "terminalEvidence":"typed-response-and-pinned-pure-interpretation",
                "authenticatedWake":false, "intervalSource":"authored-completion"
            }),
            id if Operation::parse(id).is_some_and(Operation::follows_proposal) => json!({
                "name":"proposal", "profile":"breg-proposal",
                "acceptedBinding":["proposalId","submissionVersion"],
                "authority":"bound-connection-profile-get-grant",
                "terminalEvidence":"current-proposal-get",
                "authenticatedWake":false,
                "defaultIntervalSeconds":crate::runtime::DEFAULT_RESULT_CHECK_SECONDS
            }),
            _ => serde_json::Value::Null,
        };
        if let Some(fields) = observation.as_object_mut() {
            fields.insert(
                "minimumIntervalSeconds".into(),
                json!(MINIMUM_OBSERVATION_INTERVAL_SECONDS),
            );
            fields.insert(
                "maximumRetryAfterSeconds".into(),
                json!(MAXIMUM_OBSERVATION_INTERVAL_SECONDS),
            );
            fields.insert(
                "observationLimit".into(),
                json!("1 + ceil(waitDurationSeconds / effectiveIntervalSeconds)"),
            );
            fields.insert(
                "deadline".into(),
                json!("original-wait-timeout-within-original-run-deadline"),
            );
            fields.insert("signalCarriesResult".into(), json!(false));
        }
        let mut http = json!({
            "maximumResponseBytes":MAXIMUM_HTTP_RESPONSE_BYTES,
            "attemptTimeoutMilliseconds":HTTP_REQUEST_TIMEOUT_MILLISECONDS,
            "connectTimeoutMilliseconds":HTTP_CONNECT_TIMEOUT_MILLISECONDS,
            "maximumMutationRetries":HTTP_MUTATION_RETRIES
        });
        if matches!(self.product, "external-http" | "evaluation") {
            let fields = http.as_object_mut().expect("HTTP contract is an object");
            fields.remove("connectTimeoutMilliseconds");
            fields.insert("connectionMayLowerLimits".into(), json!(true));
            fields.insert("redirects".into(), json!("refused"));
            if self.id == Operation::ExternalCommand.as_str() {
                fields.insert(
                    "maximumRequestBytes".into(),
                    json!(MAXIMUM_HTTP_RESPONSE_BYTES),
                );
            }
            if self.product == "evaluation" {
                fields.insert(
                    "attemptTimeoutMilliseconds".into(),
                    json!(EVALUATION_TIMEOUT_MILLISECONDS),
                );
                fields.insert(
                    "maximumRequestBytes".into(),
                    json!(MAXIMUM_HTTP_RESPONSE_BYTES),
                );
            }
        }
        json!({
            "identity":self.identity(),
            "connectionInterface":self.product,
            "authority":"current-bound-connection-authority",
            "limits":{
                "value":crate::functions::value_limits(),
                "maximumPreparationBytes":MAXIMUM_PREPARATION_BYTES,
                "attemptTimeoutSeconds":ATTEMPT_TIMEOUT_SECONDS,
                "maximumCallAttempts":MAXIMUM_ATTEMPTS,
                "maximumCallRetryDelaySeconds":RETRY_MAXIMUM_DELAY_SECONDS,
                "maximumConcurrentAttemptsPerRun":1,
                "maximumRunDurationSeconds":crate::definition::MAXIMUM_WAIT_SECONDS,
                "http":http
            },
            "completionObservation":observation
        })
    }

    pub fn identity(&self) -> OperationIdentity {
        OperationIdentity {
            id: self.id.to_owned(),
            version: self.version,
            product: self.product.to_owned(),
            effect: self.effect,
            key_requirement: self.key_requirement,
            requires_preparation: self.requires_preparation,
            recovery: self.recovery,
            read_receipt: self.read_receipt,
        }
    }
}

impl OperationIdentity {
    pub fn matches_registered(&self) -> bool {
        descriptor(&self.id).is_some_and(|registered| registered.identity() == *self)
    }
}

const fn read(id: &'static str, product: &'static str) -> OperationDescriptor {
    OperationDescriptor {
        id,
        version: 1,
        product,
        effect: EffectKind::Read,
        key_requirement: KeyRequirement::None,
        requires_preparation: false,
        recovery: RecoverySemantics::ReadAgain,
        read_receipt: false,
        declared_refusal: false,
    }
}

const fn mutation(
    id: &'static str,
    product: &'static str,
    read_receipt: bool,
    requires_preparation: bool,
) -> OperationDescriptor {
    OperationDescriptor {
        id,
        version: 1,
        product,
        effect: EffectKind::Mutation,
        key_requirement: KeyRequirement::Required,
        requires_preparation,
        recovery: if read_receipt {
            RecoverySemantics::SameCommandAndReceipt
        } else {
            RecoverySemantics::SameCommand
        },
        read_receipt,
        declared_refusal: false,
    }
}

const fn declared_read(id: &'static str, product: &'static str) -> OperationDescriptor {
    OperationDescriptor {
        declared_refusal: true,
        ..read(id, product)
    }
}

const fn declared_mutation(
    id: &'static str,
    product: &'static str,
    read_receipt: bool,
    requires_preparation: bool,
) -> OperationDescriptor {
    OperationDescriptor {
        declared_refusal: true,
        ..mutation(id, product, read_receipt, requires_preparation)
    }
}

const fn unkeyed_mutation(id: &'static str, product: &'static str) -> OperationDescriptor {
    OperationDescriptor {
        id,
        version: 1,
        product,
        effect: EffectKind::Mutation,
        key_requirement: KeyRequirement::None,
        requires_preparation: false,
        recovery: RecoverySemantics::HoldAfterDispatch,
        read_receipt: false,
        declared_refusal: false,
    }
}

const fn evaluation(id: &'static str, product: &'static str) -> OperationDescriptor {
    OperationDescriptor {
        id,
        version: 1,
        product,
        effect: EffectKind::Evaluation,
        key_requirement: KeyRequirement::None,
        requires_preparation: true,
        recovery: RecoverySemantics::HoldAfterDispatch,
        read_receipt: false,
        declared_refusal: false,
    }
}

// One registration feeds the public Operation constants, execution catalog and
// schema factories. Keep this order stable: identities and schema enums expose it.
macro_rules! operation_catalog {
    ($consumer:ident) => {
        $consumer! {
            ReadRecord => "breg.read-record/v1", read("breg"), read_record;
            SubmitMessage => "messaging.submit-message/v1", mutation("messaging", true, false), submit_message;
            ReadScheduling => "scheduling.read-service/v1", read("scheduling"), read_scheduling;
            ReadAvailability => "scheduling.read-availability/v1", read("scheduling"), read_availability;
            CreateAppointment => "scheduling.create-appointment/v1", mutation("scheduling", true, false), create_appointment;
            ReadAppointment => "scheduling.read-appointment/v1", read("scheduling"), read_appointment;
            CreateHold => "scheduling.create-hold/v1", mutation("scheduling", false, false), create_hold;
            ReleaseHold => "scheduling.release-hold/v1", unkeyed_mutation("scheduling"), release_hold;
            ConfirmHold => "scheduling.confirm-hold/v1", mutation("scheduling", true, false), confirm_hold;
            RescheduleAppointment => "scheduling.reschedule-appointment/v1", mutation("scheduling", false, false), reschedule_appointment;
            CancelAppointment => "scheduling.cancel-appointment/v1", mutation("scheduling", false, false), cancel_appointment;
            InvokeBregAction => "breg.invoke-action/v1", declared_mutation("breg", false, true), invoke_breg_action;
            ExternalGet => "external.get/v1", read("external-http"), external_get;
            EvaluateDecision => "evaluation.evaluate/v1", evaluation("evaluation"), evaluate;
            SubmitReviewRequest => "casework.submit-review-request/v1", mutation("casework", false, false), submit_review_request;
            CancelReviewRequest => "casework.cancel-review-request/v1", mutation("casework", false, false), cancel_review_request;
            PreviewAvailability => "scheduling.preview-availability/v1", read("scheduling"), preview_availability;
            ExternalCommand => "external.command/v1", declared_mutation("external-http", false, false), external_command;
            ReadInForce => "breg.read-in-force/v1", declared_read("breg"), read_in_force;
            ReadProposal => "breg.read-proposal/v1", read("breg"), read_proposal;
            StartProposal => "breg.start-proposal/v1", mutation("breg", false, true), start_proposal;
            SubmitProposal => "breg.submit-proposal/v1", mutation("breg", false, true), submit_proposal;
            CancelProposal => "breg.cancel-proposal/v1", mutation("breg", false, true), cancel_proposal;
        }
    };
}
pub(crate) use operation_catalog;

macro_rules! execution_catalog {
    ($($name:ident => $id:literal, $builder:ident($($argument:expr),*), $schema:ident;)+) => {
        static CATALOG: &[OperationDescriptor] = &[$($builder($id, $($argument),*)),+];
    };
}
operation_catalog!(execution_catalog);

pub fn descriptors() -> &'static [OperationDescriptor] {
    CATALOG
}

pub fn descriptor(identifier: &str) -> Option<&'static OperationDescriptor> {
    CATALOG
        .iter()
        .find(|descriptor| descriptor.id == identifier)
}

pub fn identities() -> Vec<OperationIdentity> {
    CATALOG.iter().map(OperationDescriptor::identity).collect()
}

/// Reviewed value-free operation diagnostics. Unknown remote text is never
/// copied into protected state or operator reports.
pub fn failure_code(code: &str) -> Option<&'static str> {
    match code {
        "completion-invalid-response" => Some("completion-invalid-response"),
        "completion-interpretation-failed" => Some("completion-interpretation-failed"),
        "completion-unavailable" => Some("completion-unavailable"),
        "observation-budget-exhausted" => Some("observation-budget-exhausted"),
        "review-request-unknown" => Some("review-request-unknown"),
        "review-result-expired" => Some("review-result-expired"),
        "completion-unusable-retry-after" => Some("completion-unusable-retry-after"),
        "external-unusable-retry-after" => Some("external-unusable-retry-after"),
        "action-contract-changed" => Some("action-contract-changed"),
        "action-contract-missing" => Some("action-contract-missing"),
        "target-conditions-mismatch" => Some("target-conditions-mismatch"),
        "action-unavailable" => Some("action-unavailable"),
        "prepared-command-mismatch" => Some("prepared-command-mismatch"),
        "external-invalid-command" => Some("external-invalid-command"),
        "external-destination-refused" => Some("external-destination-refused"),
        "external-redirect" => Some("external-redirect"),
        "external-invalid-response" => Some("external-invalid-response"),
        "external-unavailable" => Some("external-unavailable"),
        "external-rate-limited" => Some("external-rate-limited"),
        "external-uncertain" => Some("external-uncertain"),
        "external-interpretation-failed" => Some("external-interpretation-failed"),
        "decision-invalid-command" => Some("decision-invalid-command"),
        "decision-invalid-response" => Some("decision-invalid-response"),
        "decision-unavailable" => Some("decision-unavailable"),
        "decision-uncertain" => Some("decision-uncertain"),
        "decision-refused" => Some("decision-refused"),
        "in-force-ambiguous" => Some("in-force-ambiguous"),
        "proposal-unreadable" => Some("proposal-unreadable"),
        "proposal-handoff-refused" => Some("proposal-handoff-refused"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Operation;

    #[test]
    fn existing_portable_names_and_registration_order_are_stable() {
        // Keep this wire-compatibility fixture independent of the registration macro.
        let expected = [
            (Operation::ReadRecord, "breg.read-record/v1"),
            (Operation::SubmitMessage, "messaging.submit-message/v1"),
            (Operation::ReadScheduling, "scheduling.read-service/v1"),
            (
                Operation::ReadAvailability,
                "scheduling.read-availability/v1",
            ),
            (
                Operation::CreateAppointment,
                "scheduling.create-appointment/v1",
            ),
            (Operation::ReadAppointment, "scheduling.read-appointment/v1"),
            (Operation::CreateHold, "scheduling.create-hold/v1"),
            (Operation::ReleaseHold, "scheduling.release-hold/v1"),
            (Operation::ConfirmHold, "scheduling.confirm-hold/v1"),
            (
                Operation::RescheduleAppointment,
                "scheduling.reschedule-appointment/v1",
            ),
            (
                Operation::CancelAppointment,
                "scheduling.cancel-appointment/v1",
            ),
            (Operation::InvokeBregAction, "breg.invoke-action/v1"),
            (Operation::ExternalGet, "external.get/v1"),
            (Operation::EvaluateDecision, "evaluation.evaluate/v1"),
            (
                Operation::SubmitReviewRequest,
                "casework.submit-review-request/v1",
            ),
            (
                Operation::CancelReviewRequest,
                "casework.cancel-review-request/v1",
            ),
            (
                Operation::PreviewAvailability,
                "scheduling.preview-availability/v1",
            ),
            (Operation::ExternalCommand, "external.command/v1"),
            (Operation::ReadInForce, "breg.read-in-force/v1"),
            (Operation::ReadProposal, "breg.read-proposal/v1"),
            (Operation::StartProposal, "breg.start-proposal/v1"),
            (Operation::SubmitProposal, "breg.submit-proposal/v1"),
            (Operation::CancelProposal, "breg.cancel-proposal/v1"),
        ];
        assert_eq!(
            descriptors()
                .iter()
                .map(|entry| entry.id)
                .collect::<Vec<_>>(),
            expected.iter().map(|(_, name)| *name).collect::<Vec<_>>()
        );
        for (operation, name) in expected {
            let encoded = serde_json::to_value(operation).unwrap();
            assert_eq!(encoded, name);
            assert_eq!(
                serde_json::from_value::<Operation>(encoded).unwrap(),
                operation
            );
            assert_eq!(Operation::parse(name), Some(operation));
        }
        assert!(Operation::parse("arbitrary-post").is_none());
        let error =
            serde_json::from_value::<Operation>("unregistered-sensitive-value".into()).unwrap_err();
        assert!(!error.to_string().contains("unregistered-sensitive-value"));
    }

    #[test]
    fn operations_use_registered_execution_semantics() {
        let mut names = std::collections::BTreeSet::new();
        for registered in descriptors() {
            assert!(names.insert(registered.id));
            let operation = Operation::parse(registered.id).unwrap();
            assert_eq!(operation.product(), registered.product);
            assert_eq!(operation.recovery(), registered.recovery);
            assert_eq!(operation.supports_read_receipt(), registered.read_receipt);
            assert_eq!(
                operation.requires_key(),
                registered.key_requirement == KeyRequirement::Required
            );
            assert_eq!(
                operation.requires_preparation(),
                registered.requires_preparation
            );
            assert_eq!(
                operation.is_mutating(),
                registered.effect == EffectKind::Mutation
            );
            assert_eq!(operation.is_read(), registered.effect == EffectKind::Read);
        }
        assert!(Operation::InvokeBregAction.is_mutating());
        assert!(Operation::InvokeBregAction.requires_key());
        assert_eq!(
            Operation::InvokeBregAction.recovery(),
            RecoverySemantics::SameCommand
        );
        assert!(!Operation::InvokeBregAction.supports_read_receipt());
        assert!(Operation::InvokeBregAction.requires_preparation());
        assert!(Operation::ReadAppointment.is_read());
        assert_eq!(
            Operation::ReadAppointment.recovery(),
            RecoverySemantics::ReadAgain
        );
        for operation in [
            Operation::CreateHold,
            Operation::RescheduleAppointment,
            Operation::CancelAppointment,
        ] {
            assert!(operation.is_mutating());
            assert!(operation.requires_key());
            assert_eq!(operation.recovery(), RecoverySemantics::SameCommand);
            assert!(!operation.supports_read_receipt());
        }
        assert!(Operation::ReleaseHold.is_mutating());
        assert!(!Operation::ReleaseHold.requires_key());
        assert_eq!(
            Operation::ReleaseHold.recovery(),
            RecoverySemantics::HoldAfterDispatch
        );
        assert!(!Operation::ReleaseHold.can_retry_after_unknown());
        assert!(Operation::ConfirmHold.requires_key());
        assert_eq!(
            Operation::ConfirmHold.recovery(),
            RecoverySemantics::SameCommandAndReceipt
        );
        assert!(Operation::ConfirmHold.supports_read_receipt());
        assert!(Operation::ReadInForce.is_read());
        assert!(!Operation::ReadInForce.requires_key());
        assert!(!Operation::ReadInForce.requires_preparation());
        assert!(!Operation::ReadInForce.has_dispatch_risk());
        assert!(!Operation::ReadInForce.supports_read_receipt());
        assert_eq!(Operation::ReadInForce.product(), "breg");
        assert_eq!(
            Operation::ReadInForce.recovery(),
            RecoverySemantics::ReadAgain
        );
        assert!(Operation::ReadInForce.descriptor().declared_refusal);
        assert_eq!(
            failure_code("in-force-ambiguous"),
            Some("in-force-ambiguous")
        );
        assert!(Operation::ExternalGet.is_read());
        assert!(!Operation::ExternalGet.requires_key());
        assert!(!Operation::ExternalGet.requires_preparation());
        assert!(Operation::ExternalCommand.is_mutating());
        assert!(Operation::ExternalCommand.requires_key());
        assert!(Operation::ExternalCommand.has_dispatch_risk());
        assert!(Operation::ExternalCommand.can_retry_after_unknown());
        assert!(!Operation::ExternalCommand.requires_preparation());
        assert!(!Operation::ExternalCommand.supports_read_receipt());
        assert_eq!(Operation::ExternalCommand.product(), "external-http");
        assert_eq!(
            Operation::ExternalCommand.recovery(),
            RecoverySemantics::SameCommand
        );
        assert!(Operation::ExternalCommand.descriptor().declared_refusal);
        let http =
            Operation::ExternalCommand.descriptor().host_contract()["limits"]["http"].clone();
        assert_eq!(http["maximumRequestBytes"], MAXIMUM_HTTP_RESPONSE_BYTES);
        assert_eq!(http["maximumResponseBytes"], MAXIMUM_HTTP_RESPONSE_BYTES);
        assert_eq!(http["redirects"], "refused");
        assert_eq!(http["connectionMayLowerLimits"], true);
        assert!(
            Operation::ExternalGet.descriptor().host_contract()["limits"]["http"]
                .get("maximumRequestBytes")
                .is_none()
        );
        assert!(Operation::EvaluateDecision.is_evaluation());
        assert!(!Operation::EvaluateDecision.is_mutating());
        assert!(!Operation::EvaluateDecision.is_read());
        assert!(Operation::EvaluateDecision.has_dispatch_risk());
        assert!(!Operation::EvaluateDecision.can_retry_after_unknown());
        assert!(!Operation::EvaluateDecision.requires_key());
        assert!(Operation::EvaluateDecision.requires_preparation());
        assert!(!Operation::EvaluateDecision.supports_read_receipt());
        for review in [
            Operation::SubmitReviewRequest,
            Operation::CancelReviewRequest,
        ] {
            assert_eq!(review.product(), "casework");
            assert!(review.is_mutating());
            assert!(review.requires_key());
            assert!(!review.requires_preparation());
            assert!(!review.supports_read_receipt());
            assert_eq!(review.recovery(), RecoverySemantics::SameCommand);
        }
    }

    #[test]
    fn no_operation_decides_a_proposal() {
        // BReg and its review authority approve, reject, decide and apply
        // Proposals. A run starts, submits, cancels or follows one only.
        for registered in descriptors() {
            let verb = registered
                .id
                .split_once('.')
                .and_then(|(_, rest)| rest.split(['-', '/']).next())
                .unwrap();
            assert!(
                !["approve", "reject", "decide", "apply"].contains(&verb),
                "{}",
                registered.id
            );
        }
        for operation in [
            Operation::ReadProposal,
            Operation::StartProposal,
            Operation::SubmitProposal,
            Operation::CancelProposal,
        ] {
            assert_eq!(operation.product(), "breg");
            assert!(operation.takes_proposal_action());
        }
        assert!(Operation::ReadProposal.is_read());
        for operation in [
            Operation::StartProposal,
            Operation::SubmitProposal,
            Operation::CancelProposal,
        ] {
            assert!(operation.requires_key());
            assert_eq!(operation.recovery(), RecoverySemantics::SameCommand);
        }
        assert!(Operation::SubmitProposal.follows_proposal());
        assert!(!Operation::CancelProposal.follows_proposal());
        assert_eq!(
            Operation::StartProposal.descriptor().host_contract()["completionObservation"]
                ["profile"],
            "breg-proposal"
        );
    }

    #[test]
    fn pinned_identity_rejects_changed_registered_semantics() {
        let original = Operation::SubmitMessage.identity();
        let encoded = serde_json::to_value(&original).unwrap();
        assert_eq!(
            serde_json::from_value::<OperationIdentity>(encoded).unwrap(),
            original
        );
        assert!(original.matches_registered());
        let mut changes = Vec::new();
        let mut value = original.clone();
        value.id = "unregistered".into();
        changes.push(value);
        let mut value = original.clone();
        value.version += 1;
        changes.push(value);
        let mut value = original.clone();
        value.product = "breg".into();
        changes.push(value);
        let mut value = original.clone();
        value.effect = EffectKind::Read;
        changes.push(value);
        let mut value = original.clone();
        value.key_requirement = KeyRequirement::None;
        changes.push(value);
        let mut value = original.clone();
        value.requires_preparation = true;
        changes.push(value);
        let mut value = original.clone();
        value.recovery = RecoverySemantics::ReadAgain;
        changes.push(value);
        let mut value = original.clone();
        value.read_receipt = false;
        changes.push(value);
        for changed in changes {
            assert!(!changed.matches_registered());
        }
        assert!(identities()
            .iter()
            .all(OperationIdentity::matches_registered));
    }

    #[test]
    fn operation_diagnostics_allow_only_reviewed_value_free_categories() {
        for code in [
            "action-unavailable",
            "prepared-command-mismatch",
            "external-invalid-command",
            "external-destination-refused",
            "external-redirect",
            "external-invalid-response",
            "external-unavailable",
            "external-rate-limited",
            "external-uncertain",
            "external-interpretation-failed",
        ] {
            assert_eq!(failure_code(code), Some(code));
        }
        assert!(failure_code("remote error carrying private-canary-value").is_none());
    }

    #[cfg(feature = "schema")]
    #[test]
    fn authoring_schema_lists_the_registered_identifiers() {
        let schema = schemars::schema_for!(Operation);
        let value = serde_json::to_value(schema).unwrap();
        let names = value["enum"].as_array().unwrap();
        assert_eq!(names.len(), descriptors().len());
        for registered in descriptors() {
            assert!(names.contains(&serde_json::Value::String(registered.id.into())));
        }
    }
}
