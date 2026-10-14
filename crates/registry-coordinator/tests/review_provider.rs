// SPDX-License-Identifier: Apache-2.0
//! Exact authored policy identity and fixed terminal Review meanings.
use registry_coordinator::{definition::Definition, review_provider::policy_binding};
use serde_json::{json, Value};

pub fn project() -> Value {
    json!({"apiVersion":"id.registrystack.org/formats/coordinator/project/v1alpha1","kind":"CoordinatorProject","project":{"id":"proposal-assessment","version":"1"},"workflow":{"input":{"type":"object"},"deadlineSeconds":600,"review":{"outcomes":{"accepted":{"status":"approved"}}},"start":"done","steps":{"done":{"type":"finish","outcome":"accepted"}},"outcomes":{"accepted":{"type":"null"}}}})
}

pub fn definition(project: &Value) -> Definition {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("workflow.yaml"),
        serde_json::to_string(project).unwrap(),
    )
    .unwrap();
    Definition::load(root.path()).unwrap()
}

#[test]
fn derived_policy_pins_workflow_and_mapping_without_duplicate_identity() {
    let project = project();
    let original = definition(&project);
    let binding = policy_binding(&original.workflow, &original.digest)
        .unwrap()
        .unwrap();
    assert_eq!(binding.id, "proposal-assessment");
    assert_eq!(binding.version, "1");
    assert_eq!(binding.digest.as_str(), original.digest);
    assert_eq!(
        original
            .workflow
            .review
            .as_ref()
            .unwrap()
            .result_retention_seconds,
        86400
    );
    let mut changed = project.clone();
    changed["workflow"]["review"]["outcomes"]["accepted"] =
        json!({"status":"rejected","outcome":"assessment-refused"});
    assert_ne!(definition(&changed).digest, original.digest);
    let mut changed = project;
    changed["workflow"]["review"]["resultRetentionSeconds"] = json!(900);
    assert_ne!(definition(&changed).digest, original.digest);
    let restored = Definition::from_snapshot(&original.snapshot().unwrap()).unwrap();
    assert_eq!(
        policy_binding(&restored.workflow, &restored.digest).unwrap(),
        Some(binding)
    );
}

#[test]
fn terminal_mapping_refuses_missing_extra_and_ambiguous_approval_payloads() {
    for mapping in [
        json!({}),
        json!({"accepted":{"status":"approved"},"extra":{"status":"cancelled"}}),
        json!({"accepted":{"status":"approved","outcome":"claimed-approval"}}),
        json!({"accepted":{"status":"rejected"}}),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut project = project();
        project["workflow"]["review"]["outcomes"] = mapping;
        std::fs::write(
            root.path().join("workflow.yaml"),
            serde_json::to_string(&project).unwrap(),
        )
        .unwrap();
        assert!(Definition::load(root.path()).is_err());
    }
}
