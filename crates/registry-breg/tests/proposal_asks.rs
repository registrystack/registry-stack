// SPDX-License-Identifier: Apache-2.0
#[path = "support/proposal_hooks_model.rs"]
#[allow(dead_code)]
mod model;

#[test]
fn applicant_can_hold_answer_authority() {
    let mut source = model::source(serde_json::json!([]));
    source["accessProfiles"]["clerk"]["permissions"]["proposals"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("answer"));
    let source = registry_breg::contract::parse_project_json(&serde_json::to_vec(&source).unwrap());
    assert!(
        source.is_ok(),
        "answer is a Proposal operation: {:?}",
        source.err()
    );
    let registry = registry_breg::compiler::compile_project(
        &source.unwrap(),
        &[],
        registry_breg::compiler::CompileProfile::Authoring,
    );
    assert!(
        registry.is_ok(),
        "answer authority compiles: {:?}",
        registry.err()
    );
}

#[test]
fn ask_hooks_and_event_schema_share_the_transition_vocabulary() {
    for name in ["asked", "answered"] {
        let hook = model::local_hook("ask-observer", serde_json::json!([name]));
        let project = registry_breg::contract::parse_project_json(
            &serde_json::to_vec(&model::source(serde_json::json!([hook]))).unwrap(),
        );
        assert!(project.is_ok(), "ask lifecycle hooks parse: {name}");
        let schema = registry_breg::proposal_hooks::proposal_event_schema();
        assert!(schema["properties"]["transition"]["enum"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(name)));
    }
}

#[test]
fn answer_openapi_declares_the_exact_problem_set_and_closed_ask_documents() {
    use registry_breg::problem::ProblemCode as Code;
    use std::collections::BTreeSet;
    let mut source = model::source(serde_json::json!([]));
    source["accessProfiles"]["clerk"]["permissions"]["proposals"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("answer"));
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
    let operation = &api["paths"]["/v1/proposals/{proposal_id}/asks/{ask_id}/answer"]["post"];
    assert_eq!(operation["operationId"], "proposals.answer");
    let expected = BTreeSet::from([
        Code::AuthenticationRefused,
        Code::ResourceNotFound,
        Code::ServiceUnavailable,
        Code::SourceUnavailable,
        Code::RequestTimeout,
        Code::RequestInvalid,
        Code::PreconditionFailed,
        Code::MutationConflict,
        Code::IdempotencyConflict,
        Code::IdempotencyExpired,
        Code::ProposalRejected,
        Code::PreconditionRequired,
        Code::UnsupportedMediaType,
    ])
    .into_iter()
    .map(|code| code.code().to_owned())
    .collect::<BTreeSet<_>>();
    let actual = operation["responses"]
        .as_object()
        .unwrap()
        .values()
        .filter_map(|response| {
            response["content"]["application/problem+json"]["examples"].as_object()
        })
        .flat_map(|examples| examples.keys().cloned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    let schema = &operation["responses"]["200"]["content"]["application/json"]["schema"];
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["asks"]["items"]["additionalProperties"],
        false
    );
    let body = &operation["requestBody"]["content"]["application/json"]["schema"];
    assert_eq!(body["additionalProperties"], false);
    assert_eq!(body["properties"]["additions"]["maxItems"], 32);
}
