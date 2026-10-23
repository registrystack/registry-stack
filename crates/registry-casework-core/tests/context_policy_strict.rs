// SPDX-License-Identifier: Apache-2.0
//! Both context modes have a closed authoring shape, including the submitted
//! mode that remains a public unit variant.

use registry_casework_core::{CaseworkProject, ContentDigest, ReviewContextPolicy};
use serde_json::json;

const STANDALONE: &str =
    include_str!("../../../products/casework/examples/standalone-decision/casework.yaml");
const ADVANCED: &str =
    include_str!("../../../products/casework/examples/multi-stage-routing-clocks/casework.yaml");

#[test]
fn submitted_context_refuses_unknown_members_in_json_and_located_yaml() {
    assert!(serde_json::from_value::<ReviewContextPolicy>(
        json!({"mode":"submitted","conformanceUnknown":42})
    )
    .is_err());

    let changed = STANDALONE.replacen(
        "context: {mode: submitted}",
        "context: {mode: submitted, conformanceUnknown: 42}",
        1,
    );
    assert_ne!(changed, STANDALONE);
    let report = CaseworkProject::read("casework.yaml", changed.as_bytes()).unwrap_err();
    let finding = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.path == "/reviewPolicies/decision/context/conformanceUnknown")
        .expect("the unknown context member has its own location");
    assert_eq!(finding.code, "config.unknown-key");
    assert!(finding.source.as_ref().and_then(|site| site.line).is_some());
    assert!(finding
        .source
        .as_ref()
        .and_then(|site| site.column)
        .is_some());
}

#[test]
fn canonical_context_modes_keep_their_wire_shape() {
    let submitted: ReviewContextPolicy =
        serde_json::from_value(json!({"mode":"submitted"})).unwrap();
    assert_eq!(submitted, ReviewContextPolicy::Submitted);
    assert_eq!(
        serde_json::to_value(submitted).unwrap(),
        json!({"mode":"submitted"})
    );
    CaseworkProject::read("casework.yaml", STANDALONE.as_bytes()).unwrap();

    let contract = json!({
        "id":"urn:registry:review-context:facility-address",
        "revision":ContentDigest::for_bytes(b"revision"),
        "schemaDigest":ContentDigest::for_bytes(b"schema")
    });
    let source: ReviewContextPolicy = serde_json::from_value(json!({
        "mode":"current-source", "provider":"facility-context", "contract":contract
    }))
    .unwrap();
    assert!(matches!(source, ReviewContextPolicy::CurrentSource { .. }));
    assert_eq!(
        serde_json::to_value(source).unwrap()["mode"],
        "current-source"
    );
    assert!(serde_json::from_value::<ReviewContextPolicy>(json!({
        "mode":"current-source", "provider":"facility-context",
        "contract":contract, "conformanceUnknown":42
    }))
    .is_err());
}

#[test]
fn project_check_keeps_a_positioned_duplicate_label_warning() {
    let changed = STANDALONE.replacen(
        "  decisions:\n    label: Decisions awaiting review\n",
        "  decisions:\n    label: Decisions awaiting review\n  decisions-copy:\n    label: decisions awaiting review\n",
        1,
    );
    let decoded = CaseworkProject::read("casework.yaml", changed.as_bytes())
        .unwrap_or_else(|report| panic!("{}", report.render_human()));
    let warnings = decoded.document.warnings();
    let finding = warnings
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "casework.project.duplicate-queue-label")
        .expect("the duplicate label warning survives project decoding");
    assert_eq!(finding.path, "/queues/decisions-copy/label");
    assert_eq!(finding.related[0].path, "/queues/decisions/label");
    assert!(finding.message.contains("`decisions`"));
    assert!(finding.message.contains("`decisions-copy`"));
    assert!(!finding.message.contains("Decisions awaiting review"));
}

#[test]
fn queue_labels_refuse_tab_line_feed_and_carriage_return() {
    for (escaped, character) in [("\\t", '\t'), ("\\n", '\n'), ("\\r", '\r')] {
        let changed = STANDALONE.replacen(
            "label: Decisions awaiting review",
            &format!("label: \"Decisions{escaped}awaiting review\""),
            1,
        );
        let report = CaseworkProject::read("casework.yaml", changed.as_bytes())
            .expect_err("a queue label must be one line");
        let finding = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "casework.queue.invalid-label")
            .unwrap_or_else(|| {
                panic!("missing queue label refusal for {character:?}: {report:#?}")
            });
        assert_eq!(finding.path, "/queues/decisions/label");
    }
}

#[test]
fn team_and_outcome_labels_refuse_tab_line_feed_and_carriage_return() {
    for character in ['\t', '\n', '\r'] {
        let invalid = format!("Regional{character}review");

        let mut team_project = CaseworkProject::read("casework.yaml", ADVANCED.as_bytes())
            .unwrap()
            .value;
        team_project.teams[0].label.clone_from(&invalid);
        assert!(team_project
            .findings()
            .iter()
            .any(|finding| finding.pointer == "/teams/regional-team/label"));

        let mut outcome_project = CaseworkProject::read("casework.yaml", ADVANCED.as_bytes())
            .unwrap()
            .value;
        outcome_project.review_policies[0].outcomes[0]
            .label
            .clone_from(&invalid);
        assert!(outcome_project.findings().iter().any(|finding| {
            finding.pointer == "/reviewPolicies/regional-review/outcomes/approved/label"
        }));
    }
}

#[test]
fn policy_stage_and_routing_labels_are_single_line() {
    for (from, to, code, path) in [
        (
            "  regional-review:\n    label: Regional review",
            "  regional-review:\n    label: \"Regional\\nreview\"",
            "casework.review-policy.invalid-label",
            "/reviewPolicies/regional-review/label",
        ),
        (
            "label: Technical review",
            "label: \"Technical\\treview\"",
            "casework.review-policy.invalid-stage-label",
            "/reviewPolicies/regional-review/stages/0/label",
        ),
        (
            "label: Northern requests",
            "label: \"Northern\\rrequests\"",
            "casework.routing.invalid-label",
            "/reviewPolicies/regional-review/routing/0/label",
        ),
    ] {
        let changed = ADVANCED.replacen(from, to, 1);
        let report = CaseworkProject::read("casework.yaml", changed.as_bytes())
            .expect_err("compact labels must be one line");
        let finding = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .unwrap_or_else(|| panic!("missing {code}: {report:#?}"));
        assert_eq!(finding.path, path);
    }
}

#[test]
fn duplicate_stage_labels_are_warned_without_repeating_the_label() {
    let changed = ADVANCED.replacen("label: Final signoff", "label: technical review", 1);
    let decoded = CaseworkProject::read("casework.yaml", changed.as_bytes())
        .unwrap_or_else(|report| panic!("{}", report.render_human()));
    let warning = decoded
        .document
        .warnings()
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "casework.review-policy.duplicate-stage-label")
        .cloned()
        .expect("duplicate stage labels produce a warning");
    assert_eq!(
        warning.path,
        "/reviewPolicies/regional-review/stages/1/label"
    );
    assert_eq!(
        warning.related[0].path,
        "/reviewPolicies/regional-review/stages/0/label"
    );
    assert!(!warning.message.to_lowercase().contains("technical review"));
}

#[test]
fn project_check_keeps_duplicate_label_warnings_beside_semantic_errors() {
    let changed = STANDALONE
        .replacen(
            "  decisions:\n    label: Decisions awaiting review\n",
            "  decisions:\n    label: Decisions awaiting review\n  decisions-copy:\n    label: decisions awaiting review\n",
            1,
        )
        .replacen("reviewPolicies: [decision]", "reviewPolicies: [missing]", 1);
    let report = CaseworkProject::read("casework.yaml", changed.as_bytes())
        .expect_err("the unknown review policy refuses the project");
    for code in [
        "casework.project.duplicate-queue-label",
        "casework.review-producer.unknown-review-policy",
    ] {
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == code),
            "missing {code}: {report:#?}"
        );
    }
    assert_eq!(
        report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == "casework.project.duplicate-queue-label")
            .count(),
        1,
        "the reader warning is reported exactly once"
    );
}

#[test]
fn project_check_refuses_separator_lookalikes_in_the_queue_namespace() {
    let changed = STANDALONE.replacen(
        "  decisions:\n    label: Decisions awaiting review\n",
        "  decision-queue:\n    label: Review queue\n  decision_queue:\n    label: review queue\n",
        1,
    );
    let report = CaseworkProject::read("casework.yaml", changed.as_bytes())
        .expect_err("separator-lookalike definitions must be refused");
    let finding = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "casework.project.queue-id-collision")
        .expect("the queue collision has its own finding");
    assert_eq!(finding.path, "/queues/decision_queue");
    assert_eq!(finding.related[0].path, "/queues/decision-queue");
    assert!(finding.message.contains("`decision-queue`"));
    assert!(finding.message.contains("`decision_queue`"));
    assert_eq!(
        report
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == "casework.project.queue-id-collision")
            .count(),
        1,
        "the reader reports the collision exactly once"
    );
    let warning = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "casework.project.duplicate-queue-label")
        .expect("the label warning survives the integrity error");
    assert_eq!(warning.path, "/queues/decision_queue/label");
    assert_eq!(warning.related[0].path, "/queues/decision-queue/label");
}
