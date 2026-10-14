// SPDX-License-Identifier: Apache-2.0
//! The compact authored fixed-plan correction over public HTTP and PostgreSQL.
#![cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
#[path = "support/proposal_review_authority.rs"]
#[allow(dead_code)]
mod proposal_review_authority;

use registry_breg::{
    api::{VerifiedClaimValue, VerifiedRequestClaims},
    compiler::{compile_project, CompileProfile},
    contract::{parse_project_json, parse_project_yaml, Operation},
    model::{CompiledActionExecution, CompiledProposalReview},
};
use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegProblemCode, BRegProposal, BRegProposalState, BRegRecordFormat, BRegRecordOptions,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const SOURCE: &[u8] =
    include_bytes!("../../../products/breg/examples/refactor/reviewed-change/registry.yaml");

fn registry() -> registry_breg::CompiledRegistry {
    compile_project(
        &parse_project_yaml(SOURCE).expect("the actual adopter source parses"),
        &[],
        CompileProfile::Authoring,
    )
    .expect("the actual adopter source checks without assets or planner code")
}
fn claims(scope: &str, jurisdiction: &str) -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "directory-clerk",
        BTreeSet::from([scope.into()]),
        Some("directory-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string(jurisdiction).unwrap(),
        )]),
    )
    .unwrap()
}
fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}
fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}

fn frozen_binding(proposal: &BRegProposal) -> Value {
    json!({"id":proposal.id(), "actionId":proposal.action_id(),
        "actionRevision":proposal.action_revision(),
        "submissionVersion":proposal.submission_version(),
        "effectDigest":proposal.effect_digest()})
}

#[test]
fn compact_source_compiles_fixed_plan_and_bounded_automatic_grant() {
    let authored = registry_platform_yaml::Reader::new("registry.yaml")
        .scan(SOURCE)
        .unwrap()
        .unwrap()
        .to_json_value();
    assert!(authored["actions"][0]["execution"]["proposal"]
        .get("application")
        .is_none());
    let registry = registry();
    assert_eq!(registry.entities().len(), 1);
    let action = &registry.actions().actions[0];
    assert!(action.handler.is_none(), "fixed plans need no custom code");
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        panic!("Proposal execution")
    };
    assert!(proposal.application.is_automatic());
    assert!(matches!(
        proposal.review,
        CompiledProposalReview::Required { .. }
    ));
    let grant = proposal.system_apply_grant.as_ref().unwrap();
    assert_eq!(grant.action_id, action.id);
    assert_eq!(grant.action_revision, action.definition_revision);
    let patches = grant
        .targets
        .iter()
        .filter(|target| target.operation == Operation::Patch)
        .collect::<Vec<_>>();
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0].entity_id, "contact");
    assert_eq!(patches[0].fields, BTreeSet::from(["name".into()]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compact_reviewed_change_uses_fresh_external_approval_and_recovers_receipt() {
    let registry = registry();
    let CompiledActionExecution::Proposal { proposal } = &registry.actions().actions[0].execution
    else {
        panic!("Proposal execution")
    };
    let CompiledProposalReview::Required { policy, .. } = &proposal.review else {
        panic!("external review is required")
    };
    // This conforming substitute accepts a synthetic pin. It does not prove
    // that an independently deployed authority would accept a real policy.
    let authority = proposal_review_authority::LocalAuthority::start_for_registry(
        serde_json::from_value(serde_json::to_value(policy).unwrap()).unwrap(),
        registry.registry_id(),
    )
    .await;
    let configured = authority.registry.clone();
    let fixture = client_http::ClientFixture::start_with_mutations(
        registry,
        claims("registry:directory:write", "zone-a"),
        move |mutations| mutations.with_review_result_source(configured),
    )
    .await;
    let client = &fixture.http.client;
    let metadata = client
        .registry_contract(Some("directory-editor"))
        .await
        .unwrap();
    assert!(metadata
        .value
        .select_direct_write("records.contact.patch", "directory-editor")
        .is_err());
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.contact.create", "directory-editor")
        .unwrap()
    else {
        panic!("configured Create grant")
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"}))).unwrap(),
            &key("reviewed-contact-create"),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let id = record.value.data.record_identifier.clone();
    let options = BRegRecordOptions::default()
        .access_profile("directory-editor")
        .unwrap();
    let foreign = fixture
        .client_for(claims("registry:directory:write", "zone-b"))
        .await;
    assert_eq!(
        foreign
            .client
            .get_record("contacts", &id, &options)
            .await
            .unwrap_err()
            .problem_code(),
        Some(BRegProblemCode::ResourceNotFound)
    );
    let action = metadata
        .value
        .select_action("correct-name", "directory-editor")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"contactId":id,"name":"After"})),
        None,
    )
    .unwrap();
    let draft = client
        .start_proposal(&action, &input, &key("reviewed-name-start"))
        .await
        .unwrap()
        .value;
    assert_eq!(draft.state(), BRegProposalState::Draft);
    let submit = client
        .prepare_proposal(&draft, "submit", json!({}), &key("reviewed-name-submit"))
        .unwrap();
    let submitted = client.execute_proposal(&submit).await.unwrap().value;
    let accepted_binding = frozen_binding(&submitted);
    let calls_before_get = authority.counts();
    let observed = client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(frozen_binding(&observed), accepted_binding);
    assert_eq!(observed.state(), BRegProposalState::Submitted);
    assert_eq!(observed.revision(), submitted.revision());
    assert_eq!(
        authority.counts(),
        calls_before_get,
        "ordinary Get performs no review I/O"
    );
    assert_eq!(
        client
            .get_record("contacts", &id, &options)
            .await
            .unwrap()
            .value
            .data
            .domain_data["name"],
        "Before"
    );
    assert!(
        !fixture
            .mutations
            .run_automatic_proposal_once_for_test()
            .await
            .unwrap(),
        "submission alone cannot authorize application"
    );
    let reviewer = fixture
        .client_for(claims("registry:directory:review", "zone-a"))
        .await;
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/proposals/{}/review-context?accessProfile=directory-reviewer",
            reviewer.base_url,
            submitted.id()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let context: registry_breg_client::BRegProposalReviewDocument = response.json().await.unwrap();
    let schema = registry_breg::compiler::review_context::compile_schema(
        &fixture.registry,
        &fixture.registry.actions().actions[0],
    )
    .unwrap()
    .unwrap();
    let contract = context
        .context
        .contract
        .as_ref()
        .expect("governed review-context contract");
    assert_eq!(contract.id, schema.id);
    assert_eq!(contract.revision, schema.revision);
    assert_eq!(contract.schema_digest, schema.digest);
    assert_eq!(
        serde_json::to_value(context).unwrap()["context"]["fields"],
        json!({"contactId":id,"currentName":"Before","proposedName":"After"})
    );
    for _ in 0..2 {
        assert!(
            registry_breg::review_store::run_review_authority_once_for_test(
                &fixture.pool,
                &authority.registry
            )
            .await
            .unwrap()
        );
    }
    let before_apply = authority.counts();
    assert_eq!(before_apply.0, 1, "one authenticated external submission");
    assert_eq!(
        before_apply.2, 1,
        "approved result reconciles the exact frozen subject"
    );
    let queued_calls = authority.counts();
    let queued = client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(authority.counts(), queued_calls);
    let status = serde_json::to_value(&queued).unwrap()["applicationStatus"].clone();
    assert_eq!(status["state"], "pending");
    assert_eq!(status["mode"], "automatic");
    assert_eq!(
        status["automaticRetry"],
        json!({"scheduled":true,"attempts":0,"maximumAttempts":3})
    );
    authority.set_results_unavailable(true);
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    let outage_calls = authority.counts();
    assert_eq!(
        outage_calls.2,
        before_apply.2 + 1,
        "apply attempts a fresh authenticated result read"
    );
    let blocked = client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(
        authority.counts(),
        outage_calls,
        "blocked Get succeeds locally while authority is unavailable"
    );
    assert_eq!(frozen_binding(&blocked), accepted_binding);
    let status = serde_json::to_value(&blocked).unwrap()["applicationStatus"].clone();
    assert_eq!(status["state"], "pending");
    assert_eq!(status["reason"], "dependency-outage");
    assert!(status["recovery"]
        .as_str()
        .is_some_and(|hint| hint != "terminal"));
    assert_eq!(
        status["automaticRetry"],
        json!({"scheduled":true,"attempts":1,"maximumAttempts":3})
    );

    assert_eq!(
        client
            .get_record("contacts", &id, &options)
            .await
            .unwrap()
            .value
            .data
            .domain_data["name"],
        "Before"
    );
    authority.set_results_unavailable(false);
    // Exercise the real bounded scheduler backoff without changing persisted job state.
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    assert!(fixture
        .mutations
        .run_automatic_proposal_once_for_test()
        .await
        .unwrap());
    assert_eq!(
        authority.counts().2,
        before_apply.2 + 2,
        "retry fetches fresh approval again"
    );
    let calls_before_get = authority.counts();
    let applied = client.read_proposal(&submitted).await.unwrap().value;
    assert_eq!(
        authority.counts(),
        calls_before_get,
        "applied Get uses durable local evidence"
    );
    assert_eq!(frozen_binding(&applied), accepted_binding);
    let status = serde_json::to_value(&applied).unwrap()["applicationStatus"].clone();
    assert_eq!(status["state"], "applied");
    assert_eq!(status["mode"], "automatic");
    assert!(
        status.get("automaticRetry").is_none(),
        "terminal application has no pending retry work"
    );
    assert_eq!(applied.state(), BRegProposalState::Applied);
    assert!(applied.revision() > submitted.revision());
    let receipt = applied
        .application()
        .expect("committed application receipt");
    assert_eq!(receipt.effect_digest, submitted.effect_digest().unwrap());
    assert_eq!(receipt.submission_version, submitted.submission_version());
    assert_eq!(receipt.result_links.len(), 1);
    assert_eq!(receipt.result_links[0].record_id, id);
    assert_eq!(receipt.result_links[0].revision, 2);
    assert_eq!(
        client
            .get_record("contacts", &id, &options)
            .await
            .unwrap()
            .value
            .data
            .domain_data["name"],
        "After"
    );
    let calls = authority.counts();
    let recovered_start = client
        .start_proposal(&action, &input, &key("reviewed-name-start"))
        .await
        .unwrap()
        .value;
    assert_eq!(
        serde_json::to_value(recovered_start).unwrap(),
        serde_json::to_value(&draft).unwrap(),
        "Start recovery retains its exact request/key and original response, independent of applied Get"
    );
    let recovered = client.execute_proposal(&submit).await.unwrap().value;
    assert_eq!(
        serde_json::to_value(recovered).unwrap(),
        serde_json::to_value(submitted).unwrap(),
        "exact replay recovers the original submission response"
    );
    assert_eq!(
        authority.counts(),
        calls,
        "receipt recovery performs no external review I/O"
    );
    assert!(
        !fixture
            .mutations
            .run_automatic_proposal_once_for_test()
            .await
            .unwrap(),
        "committed application does not execute twice"
    );
    drop(reviewer);
    drop(foreign);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exact_submission_observation_rejects_revised_and_rebased_successors() {
    for transition in ["revise", "rebase"] {
        let mut source = registry_platform_yaml::Reader::new("registry.yaml")
            .scan(SOURCE)
            .unwrap()
            .unwrap()
            .to_json_value();
        // This proof adds only the lifecycle powers it explicitly exercises.
        source["accessProfiles"][0]["permissions"]["proposals"][0]["operations"] =
            json!(["get", "list", "submit", "cancel", "revise", "rebase", "retry"]);
        let registry = compile_project(
            &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
            &[],
            CompileProfile::Authoring,
        )
        .unwrap();
        let CompiledActionExecution::Proposal { proposal } =
            &registry.actions().actions[0].execution
        else {
            panic!("Proposal")
        };
        let CompiledProposalReview::Required { policy, .. } = &proposal.review else {
            panic!("required review")
        };
        let authority = proposal_review_authority::LocalAuthority::start_for_registry(
            serde_json::from_value(serde_json::to_value(policy).unwrap()).unwrap(),
            registry.registry_id(),
        )
        .await;
        let configured = authority.registry.clone();
        let fixture = client_http::ClientFixture::start_with_mutations(
            registry,
            // This journey exercises operator Retry as well as observation.
            // The explicit grant still requires an actual verified human.
            VerifiedRequestClaims::authenticated_with_actor_kind(
                "registry_principal",
                "directory-clerk",
                BTreeSet::from(["registry:directory:write".into()]),
                Some("directory-administration".into()),
                BTreeMap::from([(
                    "jurisdiction".into(),
                    VerifiedClaimValue::direct_string("zone-a").unwrap(),
                )]),
                registry_platform_oidc::ActorKind::Human,
            )
            .unwrap(),
            move |mutations| mutations.with_review_result_source(configured),
        )
        .await;
        let client = &fixture.http.client;
        let metadata = client
            .registry_contract(Some("directory-editor"))
            .await
            .unwrap();
        let BRegDirectWrite::Create(create) = metadata
            .value
            .select_direct_write("records.contact.create", "directory-editor")
            .unwrap()
        else {
            panic!("Create")
        };
        let record = client
            .create_record(
                &create,
                &BRegCreateRequest::new(map(json!({"name":"Before","jurisdiction":"zone-a"})))
                    .unwrap(),
                &key("observation-create"),
                BRegRecordFormat::Json,
            )
            .await
            .unwrap();
        let action = metadata
            .value
            .select_action("correct-name", "directory-editor")
            .unwrap();
        let values = json!({"contactId":record.value.data.record_identifier,"name":"After"});
        let input = BRegActionInvocationRequest::new(&action, map(values.clone()), None).unwrap();
        let draft = client
            .start_proposal(&action, &input, &key("observation-start"))
            .await
            .unwrap()
            .value;
        let submit = client
            .prepare_proposal(&draft, "submit", json!({}), &key("observation-submit-one"))
            .unwrap();
        let untouched = client.read_proposal(&draft).await.unwrap().value;
        assert_eq!(
            untouched.state(),
            BRegProposalState::Draft,
            "Get cannot execute the saved but unsent Submit"
        );
        assert!(untouched.effect_digest().is_none());
        assert!(
            serde_json::to_value(&untouched)
                .unwrap()
                .get("applicationStatus")
                .is_none(),
            "drafts expose no frozen application status"
        );
        let submitted = client.execute_proposal(&submit).await.unwrap().value;
        let accepted_binding = frozen_binding(&submitted);
        let observed = client.read_proposal(&submitted).await.unwrap().value;
        assert_eq!(frozen_binding(&observed), accepted_binding);
        assert_eq!(
            authority.counts(),
            (0, 0, 0),
            "ordinary observation never drives review delivery or result reconciliation"
        );
        for _ in 0..2 {
            assert!(
                registry_breg::review_store::run_review_authority_once_for_test(
                    &fixture.pool,
                    &authority.registry,
                )
                .await
                .unwrap()
            );
        }
        // Projection/recovery proof for an existing recoverable blocked job.
        // The other journey induces a real dependency outage through fresh review I/O.
        assert_eq!(
            fixture
                .database
                .admin
                .execute(
                    "UPDATE registry_internal.registry_proposal_application_jobs
             SET state='blocked',last_error_code='dependency-outage',attempt_count=1
             WHERE proposal_id=$1 AND submission_version=1",
                    &[&uuid::Uuid::parse_str(submitted.id()).unwrap()],
                )
                .await
                .unwrap(),
            1
        );
        let calls = authority.counts();
        let blocked = client.read_proposal(&submitted).await.unwrap().value;
        assert_eq!(authority.counts(), calls);
        assert_eq!(frozen_binding(&blocked), accepted_binding);
        let status = serde_json::to_value(&blocked).unwrap()["applicationStatus"].clone();
        assert_eq!(status["state"], "blocked");
        assert_eq!(status["reason"], "dependency-outage");
        assert_eq!(status["recovery"], "retry");
        assert_eq!(
            status["automaticRetry"],
            json!({"scheduled":false,"attempts":1,"maximumAttempts":3})
        );
        assert!(
            blocked
                .link("retry")
                .unwrap()
                .availability()
                .unwrap()
                .available
        );
        let retry = client
            .prepare_proposal(&blocked, "retry", json!({}), &key("observation-retry"))
            .unwrap();
        let retried = client.execute_proposal(&retry).await.unwrap().value;
        assert_eq!(frozen_binding(&retried), accepted_binding);
        let observed = client.read_proposal(&retried).await.unwrap().value;
        assert!(
            observed.revision() > submitted.revision(),
            "workflow progress has its own current revision while the frozen binding stays fixed"
        );
        assert_eq!(
            authority.counts(),
            calls,
            "local Retry/Get do not refetch review"
        );
        let status = serde_json::to_value(&observed).unwrap()["applicationStatus"].clone();
        assert_eq!(status["state"], "pending");
        assert_eq!(
            status["automaticRetry"],
            json!({"scheduled":true,"attempts":1,"maximumAttempts":3}),
            "Retry retains its original budget"
        );
        let foreign = fixture
            .client_for(claims("registry:directory:write", "zone-b"))
            .await;
        let mut problems = Vec::new();
        for id in [submitted.id().to_owned(), uuid::Uuid::new_v4().to_string()] {
            let response = reqwest::Client::new()
                .get(format!(
                    "{}/v1/proposals/{id}?accessProfile=directory-editor",
                    foreign.base_url
                ))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
            let mut body: Value = response.json().await.unwrap();
            body.as_object_mut().unwrap().remove("traceId");
            problems.push(body);
        }
        assert_eq!(
            problems[0], problems[1],
            "concealed and absent Proposal responses differ only by trace identity"
        );
        let change = client
            .prepare_proposal(
                &observed,
                transition,
                if transition == "rebase" {
                    json!({"input":values})
                } else {
                    json!({})
                },
                &key("observation-invalidate"),
            )
            .unwrap();
        let next_draft = client.execute_proposal(&change).await.unwrap().value;
        let next = client.read_proposal(&next_draft).await.unwrap().value;
        assert_eq!(next.state(), BRegProposalState::Draft);
        assert_eq!(
            next.submission_version(),
            submitted.submission_version() + 1
        );
        assert!(serde_json::to_value(&next)
            .unwrap()
            .get("applicationStatus")
            .is_none());
        assert!(
            next.effect_digest().is_none(),
            "old frozen digest is no longer current"
        );
        assert_ne!(frozen_binding(&next), accepted_binding);
        let submit_two = client
            .prepare_proposal(&next, "submit", json!({}), &key("observation-submit-two"))
            .unwrap();
        let second = client.execute_proposal(&submit_two).await.unwrap().value;
        let later = client.read_proposal(&submitted).await.unwrap().value;
        assert_eq!(frozen_binding(&later), frozen_binding(&second));
        assert_ne!(
            frozen_binding(&later),
            accepted_binding,
            "an observer waiting on version one must not follow version two"
        );
        assert_ne!(later.effect_digest(), submitted.effect_digest());
        assert!(
            client.recover_proposal(&later, &submit).is_err(),
            "a successor observation cannot rebind the original prepared command"
        );
        let receipt = client.execute_proposal(&submit).await.unwrap().value;
        assert_eq!(
            serde_json::to_value(receipt).unwrap(),
            serde_json::to_value(submitted).unwrap(),
            "the exact saved Submit still recovers its own original receipt"
        );
        assert_eq!(authority.counts(), calls);
        drop(foreign);
        fixture.finish().await;
    }
}
