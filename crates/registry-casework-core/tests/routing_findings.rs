// SPDX-License-Identifier: Apache-2.0
//! Routing diagnostics name authored members, once per offending rule or stage.
use registry_casework_core::CaseworkProject;
use serde_json::json;

const EXAMPLE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../products/casework/examples/multi-stage-routing-clocks/casework.yaml"
));

#[test]
fn routing_findings_name_each_authored_rule_member_once() {
    CaseworkProject::read("casework.yaml", EXAMPLE.as_bytes()).unwrap();
    let text = EXAMPLE
        .replace("stage: technical", "stage: nowhere")
        .replace("fields: {region:", "fields: {zone:")
        .replace("        queue: northern-review", "        queue: missing");
    let report = CaseworkProject::read("casework.yaml", text.as_bytes()).unwrap_err();
    let actual: Vec<_> = report
        .diagnostics()
        .iter()
        .map(|finding| {
            (
                finding.code.as_str(),
                finding.path.as_str(),
                finding.source.as_ref().and_then(|source| source.line),
            )
        })
        .collect();
    assert_eq!(
        actual,
        [
            (
                "casework.routing.unknown-stage",
                "/reviewPolicies/regional-review/routing/0/when/stage",
                Some(29),
            ),
            (
                "casework.routing.unknown-field",
                "/reviewPolicies/regional-review/routing/0/when/fields/zone",
                Some(30),
            ),
            (
                "casework.routing.unknown-queue",
                "/reviewPolicies/regional-review/routing/0/queue",
                Some(31),
            ),
        ],
    );
}

#[test]
fn routing_findings_do_not_repeat_stage_queue_findings() {
    let text = EXAMPLE
        .replace("        queue: triage", "        queue: missing-first")
        .replace("        queue: signoff", "        queue: missing-second");
    let report = CaseworkProject::read("casework.yaml", text.as_bytes()).unwrap_err();
    let actual: Vec<_> = report
        .diagnostics()
        .iter()
        .map(|finding| (finding.code.as_str(), finding.path.as_str()))
        .collect();
    assert_eq!(
        actual,
        [
            (
                "casework.review-policy.unknown-queue",
                "/reviewPolicies/regional-review/stages/0/queue",
            ),
            (
                "casework.review-policy.unknown-queue",
                "/reviewPolicies/regional-review/stages/1/queue",
            ),
        ],
    );
}

#[test]
fn routing_projection_limit_points_to_the_authored_rules() {
    let project = CaseworkProject::read("casework.yaml", EXAMPLE.as_bytes()).unwrap();
    let mut value = serde_json::to_value(project.value).unwrap();
    let policy = &mut value["reviewPolicies"]["regional-review"];
    policy["routing"] = json!([]);
    for index in 0..33 {
        let field = format!("field-{index}");
        policy["displaySchema"]["properties"][&field] = json!({"type": "boolean"});
        policy["routing"].as_array_mut().unwrap().push(json!({
            "id": format!("rule-{index}"),
            "because": "Route the selected field.",
            "when": {"fields": {field: {"equals": true}}},
            "queue": "triage",
        }));
    }
    let report =
        CaseworkProject::read("casework.json", &serde_json::to_vec(&value).unwrap()).unwrap_err();
    let findings = report.diagnostics();
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(
        findings[0].code,
        "casework.routing.too-many-projection-fields"
    );
    assert_eq!(findings[0].path, "/reviewPolicies/regional-review/routing");
    assert!(value.pointer(&findings[0].path).is_some());

    value["reviewPolicies"]["regional-review"]["routing"]
        .as_array_mut()
        .unwrap()
        .pop();
    CaseworkProject::read("casework.json", &serde_json::to_vec(&value).unwrap()).unwrap();
}
