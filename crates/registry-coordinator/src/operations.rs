// SPDX-License-Identifier: Apache-2.0
//! Reviewed workflow bindings over maintained clients. This catalog owns
//! execution metadata, not product authorization or wire implementation.

use serde::{Deserialize, Serialize};

use crate::protocol::RecoverySemantics;

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

/// Binding behavior is versioned independently of the workflow. Changing a
/// descriptor changes its identity and must not silently alter an admitted run.
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

    /// The v3 snapshot ABI predates pinned descriptors and supports only these
    /// original contracts. Keep this table unchanged when adding or versioning
    /// operations; an old snapshot must not acquire newer binding behavior.
    pub fn matches_legacy(&self) -> bool {
        LEGACY_CATALOG
            .iter()
            .find(|descriptor| descriptor.id == self.id)
            .is_some_and(|descriptor| descriptor.identity() == *self)
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
    }
}

const LEGACY_CATALOG: [OperationDescriptor; 5] = [
    read("read-record", "breg"),
    mutation("submit-message", "messaging", true, false),
    read("read-scheduling", "scheduling"),
    read("read-availability", "scheduling"),
    mutation("create-appointment", "scheduling", true, false),
];

static CATALOG: &[OperationDescriptor] = &[
    LEGACY_CATALOG[0],
    LEGACY_CATALOG[1],
    LEGACY_CATALOG[2],
    LEGACY_CATALOG[3],
    LEGACY_CATALOG[4],
    mutation("invoke-breg-action", "breg", false, true),
    read("external-get", "external-http"),
    OperationDescriptor {
        id: "evaluate-decision",
        version: 1,
        product: "decision",
        effect: EffectKind::Evaluation,
        key_requirement: KeyRequirement::None,
        requires_preparation: true,
        recovery: RecoverySemantics::HoldAfterDispatch,
        read_receipt: false,
    },
];

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
        "action-unavailable" => Some("action-unavailable"),
        "prepared-command-mismatch" => Some("prepared-command-mismatch"),
        "external-invalid-command" => Some("external-invalid-command"),
        "external-destination-refused" => Some("external-destination-refused"),
        "external-redirect" => Some("external-redirect"),
        "external-invalid-response" => Some("external-invalid-response"),
        "external-unavailable" => Some("external-unavailable"),
        "decision-invalid-command" => Some("decision-invalid-command"),
        "decision-invalid-response" => Some("decision-invalid-response"),
        "decision-unavailable" => Some("decision-unavailable"),
        "decision-uncertain" => Some("decision-uncertain"),
        "decision-refused" => Some("decision-refused"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Operation;

    #[test]
    fn existing_portable_names_round_trip_through_catalog() {
        for (operation, name) in [
            (Operation::ReadRecord, "read-record"),
            (Operation::SubmitMessage, "submit-message"),
            (Operation::ReadScheduling, "read-scheduling"),
            (Operation::ReadAvailability, "read-availability"),
            (Operation::CreateAppointment, "create-appointment"),
            (Operation::InvokeBregAction, "invoke-breg-action"),
            (Operation::ExternalGet, "external-get"),
            (Operation::EvaluateDecision, "evaluate-decision"),
        ] {
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
        assert!(Operation::ExternalGet.is_read());
        assert!(!Operation::ExternalGet.requires_key());
        assert!(!Operation::ExternalGet.requires_preparation());
        assert!(Operation::EvaluateDecision.is_evaluation());
        assert!(!Operation::EvaluateDecision.is_mutating());
        assert!(!Operation::EvaluateDecision.is_read());
        assert!(Operation::EvaluateDecision.has_dispatch_risk());
        assert!(!Operation::EvaluateDecision.can_retry_after_unknown());
        assert!(!Operation::EvaluateDecision.requires_key());
        assert!(Operation::EvaluateDecision.requires_preparation());
        assert!(!Operation::EvaluateDecision.supports_read_receipt());
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
    fn legacy_snapshot_contracts_do_not_include_added_operations() {
        for identity in LEGACY_CATALOG.iter().map(OperationDescriptor::identity) {
            assert!(!identity.requires_preparation);
            assert!(identity.matches_legacy());
            assert!(identity.matches_registered());
            let mut changed = identity;
            changed.version += 1;
            assert!(!changed.matches_legacy());
        }
        assert!(!Operation::InvokeBregAction.identity().matches_legacy());
        assert!(!Operation::ExternalGet.identity().matches_legacy());
        assert!(!Operation::EvaluateDecision.identity().matches_legacy());
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
