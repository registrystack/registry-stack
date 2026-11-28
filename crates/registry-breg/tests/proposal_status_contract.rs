// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "schema")]

#[path = "support/proposal_hooks_model.rs"]
#[allow(dead_code)]
mod model;

#[test]
fn shipped_required_attachment_example_reproduces_its_openapi() {
    let source =
        include_bytes!("../../../products/breg/examples/required-attachment/registry.yaml");
    let registry = registry_breg::compiler::compile_project(
        &registry_breg::contract::parse_project_yaml(source).unwrap(),
        &[],
        registry_breg::compiler::CompileProfile::Authoring,
    )
    .unwrap();
    let generated = &registry.artifacts().entries()["generated/openapi.json"].bytes;
    let committed =
        include_bytes!("../../../products/breg/examples/required-attachment/openapi.json");
    assert!(
        generated.as_slice() == committed,
        "regenerate the required-attachment example's OpenAPI with example-artifacts"
    );
    let api: serde_json::Value = serde_json::from_slice(generated).unwrap();
    assert_eq!(
        api["paths"]["/v1/proposals/{proposal_id}/submit"]["post"]["responses"]["422"]["content"]
            ["application/problem+json"]["examples"]["attachment.required"]["value"]["fieldPath"],
        "/attachments/support"
    );
}

#[test]
fn shipped_submit_examples_use_problem_code_keys() {
    let api: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../products/breg/generated/facility/generated/openapi.json"
    ))
    .unwrap();
    let examples = api["paths"]["/v1/proposals/{proposal_id}/submit"]["post"]["responses"]["422"]
        ["content"]["application/problem+json"]["examples"]
        .as_object()
        .unwrap();
    let mut refusals = 0;
    for (key, example) in examples {
        let code = example["value"]["code"].as_str().unwrap();
        if code == "action.refused" {
            refusals += 1;
        }
        assert!(
            key == code
                || key
                    .strip_prefix(code)
                    .is_some_and(|suffix| suffix.starts_with('/')),
            "example {key} must be keyed by problem code {code}"
        );
    }
    assert!(
        refusals > 0,
        "the example must exercise declared planner refusals"
    );
}

#[test]
fn apply_declares_encryption_failure_for_an_encrypted_write() {
    let mut source = model::source(serde_json::json!([]));
    source["recordTypes"]["target"]["fields"][0]["encrypted"] = serde_json::json!(true);
    let registry = registry_breg::compiler::compile_project(
        &registry_breg::contract::parse_project_json(&serde_json::to_vec(&source).unwrap())
            .unwrap(),
        &[],
        registry_breg::compiler::CompileProfile::Authoring,
    )
    .unwrap();
    let api: serde_json::Value =
        serde_json::from_slice(&registry.artifacts().entries()["generated/openapi.json"].bytes)
            .unwrap();
    assert_eq!(
        api["paths"]["/v1/proposals/{proposal_id}/apply"]["post"]["responses"]["503"]["content"]
            ["application/problem+json"]["examples"]["runtime.field_encryption.unavailable"]
            ["value"]["code"],
        "runtime.field_encryption.unavailable"
    );
    assert!(
        api["paths"]["/v1/proposals/{proposal_id}/submit"]["post"]["responses"]["503"]["content"]
            ["application/problem+json"]["examples"]
            .get("runtime.field_encryption.unavailable")
            .is_none()
    );
}

#[test]
fn proposal_availability_objects_use_a_typed_constructor() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mutation");
    let mut files = vec![root.join("proposal.rs")];
    let mut directories = vec![root.join("proposal")];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directories.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap();
        assert!(
            !source.contains("[\"availability\"]"),
            "{}: availability must not be assembled by mutating JSON",
            path.display()
        );
        for line in source
            .lines()
            .filter(|line| line.contains("\"availability\":"))
        {
            assert!(
                line.contains("ProposalAvailability::"),
                "{}: untyped availability: {line}",
                path.display()
            );
        }
    }
}

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
    let mut optional = policy["attachments"][0].clone();
    optional["id"] = json!("supplement");
    optional["required"] = json!(false);
    policy["attachments"].as_array_mut().unwrap().push(optional);
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
            // Pin handler-level codes, independently of the schema generator:
            // read handlers conceal malformed inputs and failed preconditions;
            // raw slot bodies have their own media/size problems.
            use registry_breg::problem::ProblemCode as Code;
            let mut expected = std::collections::BTreeSet::from([
                Code::AuthenticationRefused,
                Code::ResourceNotFound,
                Code::ServiceUnavailable,
                Code::SourceUnavailable,
                Code::RequestTimeout,
            ]);
            if id == "proposals.list" {
                expected.insert(Code::QueryInvalid);
            } else if id == "proposals.get-task-grant-context" {
                expected.extend([Code::RequestInvalid, Code::UnsupportedMediaType]);
            } else if method != "get" {
                expected.extend([
                    Code::RequestInvalid,
                    Code::PreconditionFailed,
                    Code::MutationConflict,
                    Code::IdempotencyConflict,
                    Code::IdempotencyExpired,
                ]);
                if !id.ends_with(".start") {
                    expected.extend([Code::PreconditionRequired, Code::ProposalRejected]);
                }
                if method == "patch" || id.starts_with("proposals.additions.") {
                    expected.extend([Code::AttachmentContentType, Code::AttachmentTooLarge]);
                    if method == "post" {
                        expected.insert(Code::AttachmentLimitReached);
                    }
                } else if method != "delete" {
                    expected.insert(Code::UnsupportedMediaType);
                }
                if id == "proposals.submit" {
                    expected.extend([
                        Code::AttachmentRequired,
                        Code::AttachmentVerificationPending,
                        Code::AttachmentVerificationRejected,
                    ]);
                }
                if id == "proposals.apply" {
                    expected.insert(Code::ProposalReviewResultMismatch);
                }
            }
            if id == "proposals.get-submission" {
                expected.insert(Code::ProposalSubmissionExpired);
            }
            let actual = operation["responses"]
                .as_object()
                .unwrap()
                .values()
                .filter_map(|response| {
                    response["content"]["application/problem+json"]["examples"].as_object()
                })
                .flat_map(|examples| {
                    examples
                        .values()
                        .map(|example| example["value"]["code"].as_str().unwrap().to_owned())
                })
                .collect::<std::collections::BTreeSet<_>>();
            let expected = expected
                .iter()
                .map(|code| code.code().to_owned())
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                actual, expected,
                "problem code set for {id} ({method} {path})"
            );
            for (status, response) in operation["responses"].as_object().unwrap() {
                if !status.starts_with('2') {
                    let problem = &response["content"]["application/problem+json"];
                    let examples = problem["examples"]
                        .as_object()
                        .unwrap()
                        .values()
                        .map(|example| example["value"]["code"].as_str().unwrap().to_owned())
                        .collect::<std::collections::BTreeSet<_>>();
                    let declared = problem["schema"]["allOf"][1]["properties"]["code"]["enum"]
                        .as_array()
                        .map(|codes| {
                            codes
                                .iter()
                                .map(|code| code.as_str().unwrap().to_owned())
                                .collect::<std::collections::BTreeSet<_>>()
                        })
                        .unwrap_or_default();
                    assert_eq!(
                        declared, examples,
                        "{id} {status} must constrain its own problem codes"
                    );
                }
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
    let registry = registry_breg::compiler::compile_project(
        &registry_breg::contract::parse_project_json(
            &serde_json::to_vec(&model::source(serde_json::json!([]))).unwrap(),
        )
        .unwrap(),
        &[],
        registry_breg::compiler::CompileProfile::Authoring,
    )
    .unwrap();
    for path in ["generated/sdk/project.ts", "generated/sdk/project.py"] {
        let source = std::str::from_utf8(&registry.artifacts().entries()[path].bytes).unwrap();
        for (name, expected) in [
            (
                "EngineReason",
                registry_breg::lifecycle::ProposalAvailabilityReason::ALL
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<std::collections::BTreeSet<_>>(),
            ),
            (
                "RecoveryHint",
                registry_breg::lifecycle::ProposalLinkRecovery::ALL
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<std::collections::BTreeSet<_>>(),
            ),
        ] {
            let declaration = source
                .lines()
                .find(|line| {
                    line.starts_with(&format!("export type {name} ="))
                        || line.starts_with(&format!("{name} ="))
                })
                .unwrap();
            let actual = declaration
                .split('\'')
                .enumerate()
                .filter_map(|(index, value)| (index % 2 == 1).then_some(value))
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                actual, expected,
                "{path} {name} must use the served vocabulary"
            );
        }
    }
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

#[test]
fn proposal_availability_pairs_match_the_client_contract() {
    use registry_breg::lifecycle::{
        ProposalAvailability, ProposalAvailabilityReason, ProposalLinkRecovery, ProposalLinkRefusal,
    };
    use registry_breg_client::BRegProposal;
    use serde_json::json;
    let accepts = |reason, recovery| {
        ["draft", "submitted", "applied", "rejected", "cancelled"].iter().any(|state| {
            let id = "705cd4a4-526e-41ca-b88b-6ca8f82a87af";
            let digest = format!("sha256:{}", "a".repeat(64));
            let mut value = json!({"id":id,"actionId":"correct","actionRevision":digest,
                "state":state,"submissionVersion":1,"revision":2,"links":{
                    "self":{"method":"GET","path":format!("/v1/proposals/{id}"),"accessProfile":"writer","operation":"get",
                        "availability":{"available":false,"observedRevision":2,"reason":reason,"recovery":recovery}}
                }});
            if *state == "submitted" { value["effectDigest"] = json!(digest); }
            BRegProposal::from_slice(&serde_json::to_vec(&value).unwrap()).is_ok()
        })
    };
    for reason in ProposalAvailabilityReason::ALL {
        for recovery in ProposalLinkRecovery::ALL {
            let declared = ProposalLinkRefusal::ALL
                .iter()
                .any(|refusal| refusal.pair() == (*reason, *recovery));
            assert_eq!(
                accepts(reason, recovery),
                declared,
                "{reason:?}/{recovery:?}"
            );
        }
    }
    for refusal in ProposalLinkRefusal::ALL {
        let value = serde_json::to_value(ProposalAvailability::new(2, Some(*refusal))).unwrap();
        assert_eq!(value["available"], false);
        assert_eq!(
            value["reason"],
            serde_json::to_value(refusal.pair().0).unwrap()
        );
        assert_eq!(
            value["recovery"],
            serde_json::to_value(refusal.pair().1).unwrap()
        );
    }
}
