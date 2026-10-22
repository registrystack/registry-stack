// SPDX-License-Identifier: Apache-2.0
//! Approval patterns share policy semantics across submitted and source bindings.

use anyhow::{bail, Result};
use serde_json::{json, Value};

pub(crate) const PATTERN_NAMES: [&str; 3] = [
    "single-reviewer-approval",
    "two-peer-approval",
    "technical-check-then-authorization",
];
pub(crate) const TEMPLATE_NAMES: [&str; 5] = [
    "standalone-decision",
    "canonical-review",
    PATTERN_NAMES[0],
    PATTERN_NAMES[1],
    PATTERN_NAMES[2],
];

pub(crate) fn approval_project(pattern: &str) -> Result<Value> {
    if !PATTERN_NAMES.contains(&pattern) {
        bail!("unknown approval pattern");
    }
    let mut project = json!({
        "apiVersion": "id.registrystack.org/formats/casework/project/v1alpha1",
        "kind": "CaseworkProject",
        "project": {"id": pattern, "version": "1"},
        "accessProfiles": {
            "staff": {"principalClaim":"sub", "requiredScopes":["casework:staff"], "role":"staff"},
            "supervisor": {"principalClaim":"sub", "requiredScopes":["casework:supervisor"], "role":"supervisor"},
            "administrator": {"principalClaim":"sub", "requiredScopes":["casework:admin"], "role":"administrator"},
            "requester": {"principalClaim":"sub", "requiredScopes":["casework:request"], "role":"requester"}
        },
        "queues": {"reviews": {"label": "Reviews awaiting approval"}},
        "reviewPolicies": {},
        "trustedProducers": {
            "requester": {
                "profile":"requester",
                "issuer":"https://identity.example.test",
                "subject":"review-producer.example.test",
                "trustedInitiatorIssuer":"https://identity.example.test",
                "sourceNamespaces":["submitted"],
                "reviewPolicies":[pattern],
                "retention":{"receiptRetentionDays":30}
            }
        }
    });
    let mut stages = json!([{
        "id":"review", "queue":"reviews", "decidingProfiles":["staff"],
        "requiredApprovals": if pattern == "two-peer-approval" {2} else {1},
        "excludeInitiator":true
    }]);
    if pattern == "technical-check-then-authorization" {
        project["accessProfiles"]
            .as_object_mut()
            .unwrap()
            .remove("staff");
        for profile in ["technical-reviewer", "authorizer"] {
            project["accessProfiles"][profile] = json!({
                "principalClaim":"sub", "requiredScopes":[format!("casework:{profile}")], "role":"staff"
            });
        }
        project["queues"] = json!({
            "technical-checks":{"label":"Technical checks"},
            "authorizations":{"label":"Reviews awaiting authorization"}
        });
        stages = json!([
            {"id":"technical-check", "queue":"technical-checks", "decidingProfiles":["technical-reviewer"],
             "requiredApprovals":1, "excludeInitiator":true, "negativeDecisions":"advise"},
            {"id":"authorization", "queue":"authorizations", "decidingProfiles":["authorizer"],
             "requiredApprovals":1, "excludeInitiator":true, "excludePreviousStageReviewers":true}
        ]);
    }
    project["reviewPolicies"][pattern] = json!({
        "version":"1", "purpose":"approval", "context":{"mode":"submitted"},
        "stages":stages,
        "retention":{"terminalRetentionDays":30, "accountabilityRetentionDays":365},
        "displaySchema":{
            "type":"object", "additionalProperties":false,
            "required":["summary","reference"],
            "properties":{
                "summary":{"type":"string","maxLength":160},
                "reference":{"type":"string","maxLength":120}
            }
        },
        "outcomes":{
            "approved":{"label":"Approve", "settlement":"approved", "reasonRequired":false, "publicReason":"optional"},
            "rejected":{"label":"Reject", "settlement":"rejected", "reasonRequired":true, "publicReason":"optional"},
            "changes-requested":{"label":"Request changes", "settlement":"changes-requested", "reasonRequired":true, "publicReason":"optional"}
        }
    });
    Ok(project)
}

pub(crate) fn approval_dev_clients(pattern: &str) -> Result<Value> {
    let project = approval_project(pattern)?;
    let mut clients = Vec::new();
    for (id, profile) in project["accessProfiles"].as_object().unwrap() {
        let mut client = json!({"id":id, "accessProfile":id, "scopes":profile["requiredScopes"]});
        if profile["role"] != "requester" {
            client["claims"] = json!({"registry_actor_kind":"human"});
        }
        clients.push(client);
    }
    if pattern == "two-peer-approval" {
        clients.push(json!({"id":"staff-two", "accessProfile":"staff", "scopes":["casework:staff"], "claims":{"registry_actor_kind":"human"}}));
    }
    let directory = project["reviewPolicies"][pattern]["stages"].as_array().unwrap().iter().map(|stage| {
        let staff = if pattern == "two-peer-approval" {json!(["staff", "staff-two"])} else {stage["decidingProfiles"].clone()};
        json!({"team":format!("{}-team",stage["queue"].as_str().unwrap()),"queue":stage["queue"],"staff":staff,"supervisors":["supervisor"]})
    }).collect::<Vec<_>>();
    Ok(json!({
        "apiVersion":"id.registrystack.org/formats/casework/dev-clients/v1alpha1",
        "kind":"CaseworkDevClients", "clients":clients, "directory":directory
    }))
}

pub(crate) fn approval_fixture(pattern: &str) -> Result<Value> {
    let project = approval_project(pattern)?;
    Ok(json!({
        "apiVersion":"id.registrystack.org/formats/casework/fixture/v1alpha1",
        "kind":"CaseworkFixture", "id":"approval-pattern-offline",
        "review":{"policy":pattern,"display":{"summary":"Review the prepared synthetic change","reference":"synthetic-change-0042"}},
        "expect":{"queue":project["reviewPolicies"][pattern]["stages"][0]["queue"],"outcomes":["approved","changes-requested","rejected"]}
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_patterns_compile_and_package_with_their_local_people() {
        for pattern in PATTERN_NAMES {
            let root = crate::canonical_tempdir();
            let project = root.path().join("project");
            crate::project::init(&project, pattern).unwrap();
            let checked = crate::project::check(&project, false, true).unwrap();
            assert_eq!(checked["ok"], true, "template {pattern} check");
            let tested = crate::project::test(&project, true).unwrap();
            assert_eq!(tested["ok"], true, "template {pattern} fixtures");
            crate::project::package_dry_run(&project, None).unwrap();
            let compiled = crate::project::load_and_check_policy(&project).unwrap();
            let policy = compiled
                .review_policies
                .iter()
                .find(|policy| policy.id == pattern)
                .unwrap();
            assert!(policy.stages.iter().all(|stage| stage.exclude_initiator));
            let explained = crate::report::CliReport::from_value(
                "explain",
                crate::project::explain(&project).unwrap(),
            )
            .unwrap();
            let explained = serde_json::to_value(explained).unwrap();
            let stages = explained["data"]["reviewPolicies"][0]["stages"]
                .as_array()
                .unwrap();
            assert_eq!(
                stages[0]["negativeDecisions"],
                if pattern == "technical-check-then-authorization" {
                    "advise"
                } else {
                    "settle"
                }
            );
            assert_eq!(stages.last().unwrap()["negativeDecisions"], "settle");
            assert!(crate::project::init(&project, pattern).is_err());
        }
    }

    #[test]
    fn clap_and_init_share_every_template_and_reject_unknown_templates() {
        let command = crate::command();
        let init = command.find_subcommand("init").unwrap();
        let template = init
            .get_arguments()
            .find(|arg| arg.get_id() == "template")
            .unwrap();
        let actual = template
            .get_value_parser()
            .possible_values()
            .unwrap()
            .map(|value| value.get_name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(actual, TEMPLATE_NAMES);
        let root = crate::canonical_tempdir();
        let project = root.path().join("unknown");
        assert!(crate::project::init(&project, "unknown").is_err());
        assert!(!project.exists());
    }
}
