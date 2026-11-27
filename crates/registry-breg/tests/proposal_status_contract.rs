// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "schema")]

#[path = "support/proposal_hooks_model.rs"]
#[allow(dead_code)]
mod model;

#[test]
fn every_proposal_error_response_declares_its_problem_body() {
    use registry_breg::{
        compiler::{compile_project, CompileProfile},
        contract::parse_project_json,
    };
    use serde_json::{json, Value};
    let mut source = model::source(json!([]));
    source["reviewAuthorities"] =
        json!({"local-review":{"protocol":"id.registrystack.org/protocols/review/v1"}});
    let policy = &mut source["actions"]["correct-name"]["execution"]["proposal"];
    policy["attachments"][0]["required"] = json!(true);
    policy["review"] = json!({"type":"required","authority":"local-review","source":"proposal-test",
        "policy":{"id":"name-correction","version":"1","digest":format!("sha256:{}","b".repeat(64))}});
    policy["additions"] = json!({"id":"other","maximumBytes":32,"maximumCount":2,"contentTypes":["text/plain"],"classification":"restricted"});
    policy["reviewContext"]["fields"]["document"] = json!({"type":"document","slot":"support"});
    policy["reviewContext"]["fields"]["other"] = json!({"type":"additions","slot":"other"});
    let grant = &mut source["accessProfiles"]["clerk"]["permissions"]["proposals"][0];
    grant["operations"] = json!([
        "get",
        "list",
        "edit",
        "submit",
        "revise",
        "rebase",
        "cancel",
        "apply",
        "retry",
        "add",
        "get-review-status",
        "get-review-context",
        "get-task-grant-context"
    ]);
    grant["readableAttachments"] = json!(["support", "other"]);
    grant["writableAttachments"] = json!(["support", "other"]);
    grant["readableContextFields"] = json!(["value", "document", "other"]);
    grant["operations"]
        .as_array_mut()
        .unwrap()
        .retain(|operation| operation != "get-task-grant-context");
    let mut service = source["accessProfiles"]["clerk"].clone();
    service["default"] = json!(false);
    service["actorKind"] = json!("service");
    service["requesterClients"] = json!(["review-provider"]);
    service["permissions"]["proposals"][0]["operations"] = json!(["get", "get-task-grant-context"]);
    service["permissions"]["proposals"][0]["writableAttachments"] = json!([]);
    source["accessProfiles"]["review-service"] = service;
    let registry = compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap();
    let api: Value =
        serde_json::from_slice(&registry.artifacts().entries()["generated/openapi.json"].bytes)
            .unwrap();
    let mut routes = Vec::new();
    let mut omissions = Vec::new();
    let problem_schema = &api["components"]["schemas"]["Problem"];
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(problem_schema)
        .unwrap();
    for (path, item) in api["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            let Some(id) = operation["operationId"].as_str() else {
                continue;
            };
            if !path.starts_with("/v1/proposals") && !id.ends_with(".start") {
                continue;
            }
            routes.push(format!("{method} {path}"));
            for (status, response) in operation["responses"].as_object().unwrap() {
                if !status.starts_with('2')
                    && response["content"]["application/problem+json"]["schema"].is_null()
                {
                    omissions.push(format!("{method} {path}: {status}"));
                }
                if !status.starts_with('2') {
                    if let Some(examples) =
                        response["content"]["application/problem+json"]["examples"].as_object()
                    {
                        for (code, example) in examples {
                            assert!(
                                validator.is_valid(&example["value"]),
                                "{method} {path}: {status} {code}"
                            );
                        }
                    }
                }
            }
        }
    }
    for required in [
        "/submissions/",
        "/review-status",
        "/review-context",
        "/task-grant-context",
        "/attachments/",
        "/additions/",
    ] {
        assert!(
            routes.iter().any(|route| route.contains(required)),
            "fixture misses {required}"
        );
    }
    assert!(
        routes.len() >= 18,
        "fixture must cover the full Proposal surface: {routes:?}"
    );
    assert!(
        omissions.is_empty(),
        "Proposal errors lack problem schemas: {omissions:?}"
    );
    assert_eq!(
        api["paths"]["/v1/proposals/{proposal_id}/submit"]["post"]["responses"]["422"]["content"]
            ["application/problem+json"]["examples"]["attachment.required"]["value"]["code"],
        "attachment.required"
    );
}

#[test]
fn every_proposal_availability_reason_is_in_the_served_schema() {
    let served = registry_breg::artifacts::availability_schema();
    for reason in registry_breg::lifecycle::ProposalAvailabilityReason::ALL {
        let wire = serde_json::to_value(reason).unwrap();
        assert!(
            served["properties"]["reason"]["enum"]
                .as_array()
                .unwrap()
                .contains(&wire),
            "served availability schema omits {wire}"
        );
        serde_json::from_value::<registry_breg_client::BRegAvailabilityReason>(wire).unwrap();
    }
    for recovery in registry_breg::lifecycle::ProposalLinkRecovery::ALL {
        let wire = serde_json::to_value(recovery).unwrap();
        assert!(
            served["properties"]["recovery"]["enum"]
                .as_array()
                .unwrap()
                .contains(&wire),
            "served availability schema omits {wire}"
        );
        serde_json::from_value::<registry_breg_client::BRegRecoveryHint>(wire).unwrap();
    }
}
