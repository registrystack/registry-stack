// SPDX-License-Identifier: Apache-2.0

use super::*;
use registry_breg::package::MAX_MIGRATION_STATEMENTS;

fn capacity_project(profile_count: usize) -> Vec<u8> {
    let record_types = (0..3)
        .map(|target| {
            json!({
                "id": format!("case-{target}"), "primaryDataset": "cases",
                "route": format!("cases-{target}"), "mutationMode": "mutable",
                "mutationPolicy": {"patch": "proposal-required"},
                "fields": [{
                    "id": "label", "type": "string", "required": true,
                    "maximumLength": 80, "classification": "internal"
                }]
            })
        })
        .collect::<Vec<_>>();
    let targets = (0..3)
        .map(|target| {
            json!({"recordType": format!("case-{target}"), "rowBoundaries": "unrestricted"})
        })
        .collect::<Vec<_>>();
    let readable_inputs = (0..3)
        .flat_map(|target| [format!("case-{target}"), format!("case-{target}-label")])
        .collect::<Vec<_>>();
    let actions = (0..4)
        .map(|flow| {
            let inputs = (0..3)
                .flat_map(|target| {
                    [
                        json!({
                            "id": format!("case-{target}"), "type": "reference",
                            "target": format!("case-{target}"), "required": true,
                            "classification": "internal"
                        }),
                        json!({
                            "id": format!("case-{target}-label"), "type": "string",
                            "required": true, "maximumLength": 80, "classification": "internal"
                        }),
                    ]
                })
                .collect::<Vec<_>>();
            let effects = (0..3)
                .map(|target| {
                    json!({
                        "id": format!("update-{target}"),
                        "target": {"fromInput": format!("case-{target}")},
                        "operation": "patch",
                        "set": {"label": {"fromInput": format!("case-{target}-label")}}
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "id": format!("review-flow-{flow}"),
                "execution": {"mode": "proposal", "proposal": {
                    "review": {"type": "none"}, "application": {"mode": "manual"},
                    "retention": {"mode": "retain"}
                }},
                "inputs": inputs,
                "plan": {"type": "fixed", "effects": effects}
            })
        })
        .collect::<Vec<_>>();
    let access_profiles = (0..profile_count)
        .map(|profile| {
            let actions = (0..4)
                .map(|flow| {
                    json!({
                        "action": format!("review-flow-{flow}"), "operations": ["start"],
                        "targets": targets
                    })
                })
                .collect::<Vec<_>>();
            let proposals = (0..4)
                .map(|flow| {
                    json!({
                        "action": format!("review-flow-{flow}"),
                        "operations": ["get", "list", "edit", "submit", "cancel", "apply"],
                        "ownership": "caller", "readableInputs": readable_inputs,
                        "targets": targets
                    })
                })
                .collect::<Vec<_>>();
            let mut permissions = json!({"actions": actions, "proposals": proposals});
            if profile == 0 {
                permissions["records"] = json!([{
                    "recordType": "case-0", "operations": ["get", "list"],
                    "readableFields": ["label"], "rowBoundaries": "unrestricted"
                }]);
            }
            json!({
                "id": format!("reviewer-{profile}"), "default": profile == 0,
                "principalClaim": "principal", "requiredScopes": [format!("review:{profile}")],
                "permissions": permissions
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_vec(&json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {
            "id": "review-capacity", "version": "1", "defaultLanguage": "en",
            "canonicalBaseIri": "https://review-capacity.example.test"
        },
        "package": {"sourceRevision": "capacity-source"},
        "manifestProjection": {
            "accessProfile": "reviewer-0", "classificationCeiling": "internal",
            "catalog": {
                "baseUrl": "https://review-capacity.example.test",
                "title": "Review Capacity Registry",
                "publisher": {"id": "review-authority", "name": "Review Authority"}
            },
            "publicService": {"id": "review-service", "title": "Review Service"},
            "datasets": [{
                "id": "cases", "title": "Cases", "owner": "Review Authority", "status": "active"
            }],
            "dataServices": [{
                "id": "review-api", "title": "Review API",
                "endpointUrl": "https://review-capacity.example.test", "servesDatasets": ["cases"]
            }],
            "distributions": []
        },
        "datasets": [{"id": "cases"}],
        "recordTypes": record_types,
        "actions": actions,
        "accessProfiles": access_profiles
    }))
    .expect("capacity fixture serializes")
}

#[test]
fn production_check_warns_when_initial_migration_exceeds_supported_capacity() {
    let source = capacity_project(16);
    let parsed = parse_project_yaml(&source).expect("capacity fixture parses");
    let compiled = compile_project(&parsed, &[], CompileProfile::Production)
        .expect("capacity fixture compiles in production");
    let actual = compiled.ddl().statements.len();
    assert!(actual > MAX_MIGRATION_STATEMENTS);
    let project = TestProject::from_registry_source(&source);

    let authoring = bregctl(&["--format", "json", "check", path(project.path())]);
    assert!(authoring.status.success(), "{authoring:?}");
    assert!(json_stdout(&authoring)["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .all(|diagnostic| diagnostic["code"] != "breg.package.migration-statement-capacity"));

    let production = bregctl(&[
        "--format",
        "json",
        "check",
        path(project.path()),
        "--production",
    ]);
    assert!(production.status.success(), "{production:?}");
    let report = json_stdout(&production);
    let diagnostic = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == "breg.package.migration-statement-capacity")
        .expect("production check reports package migration capacity");
    let message = diagnostic["message"].as_str().unwrap();
    assert!(message.contains(&actual.to_string()), "{message}");
    assert!(
        message.contains(&MAX_MIGRATION_STATEMENTS.to_string()),
        "{message}"
    );
    assert!(message.contains("initial activation"), "{message}");
    assert!(message.contains("Baseline-derived successors"), "{message}");
    assert_eq!(diagnostic["severity"], "warning");
    assert_check_diagnostic(diagnostic, Some("BRegProject"));

    let denied = bregctl(&[
        "--format",
        "json",
        "check",
        path(project.path()),
        "--production",
        "--deny-warnings",
    ]);
    assert_eq!(denied.status.code(), Some(1), "{denied:?}");
    assert!(json_stdout(&denied)["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|diagnostic| diagnostic["code"] == "breg.package.migration-statement-capacity"));
}
