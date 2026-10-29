// SPDX-License-Identifier: Apache-2.0
//! A failed field commit guard on Proposal submit or apply answers the same
//! `action.guard_failed` problem an immediate Action answers, only when the
//! selected profile can read the facts that establish it. A stale Record
//! revision stays `precondition.failed`. A guard that compares a field with an
//! input reads that input from the frozen submission.
#![cfg(feature = "postgres-test")]
#[path = "support/client_http.rs"]
#[allow(dead_code)]
mod client_http;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use registry_breg::api::{VerifiedClaimValue, VerifiedRequestClaims};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg_client::{
    BRegActionInvocationRequest, BRegCreateRequest, BRegDirectWrite, BRegIdempotencyKey,
    BRegProblemCode, BRegProposal, BRegRecordFormat,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

fn claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated_with_actor_kind(
        "sub",
        "author",
        BTreeSet::from(["proposal:manage".into()]),
        Some("registry-administration".into()),
        BTreeMap::from([(
            "jurisdiction".into(),
            VerifiedClaimValue::direct_string("zone-a").unwrap(),
        )]),
        registry_platform_oidc::ActorKind::Human,
    )
    .unwrap()
}

fn key(value: &str) -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(value).unwrap()
}

fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

/// The guards read `status` and compare `capacity` with the `minimum` input;
/// `readable` lists what the profile may read.
fn registry(readable: &[&str]) -> registry_breg::CompiledRegistry {
    let source = json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"guard-failure-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://guard.example.test"},
        "datasets":[{"id":"directory"}],
        "recordTypes":[{"id":"target","primaryDataset":"directory","route":"targets","mutationMode":"mutable",
            "mutationPolicy":{"patch":"proposal-required"},
            "fields":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                {"id":"status","type":"string","required":true,"maximumLength":16,"classification":"internal"},
                {"id":"capacity","type":"int64","required":true,"classification":"internal"},
                {"id":"jurisdiction","type":"string","required":true,"maximumLength":64,"classification":"internal"}]}],
        "actions":[{"id":"correct-name","execution":{"mode":"proposal","proposal":{
            "review":{"type":"none"},"application":{"mode":"manual"},"retention":{"mode":"operator-erase"}}},
            "inputs":[{"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
                {"id":"value","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                {"id":"minimum","type":"int64","required":true,"classification":"internal"}],
            "commitGuards":{"targets":[
                {"input":"target","revision":"unchanged"},
                {"input":"target","field":"status","equals":"open","reason":"target-not-open"},
                {"input":"target","field":"capacity","atLeastFromInput":"minimum","reason":"below-minimum"}]},
            "plan":{"type":"fixed","effects":[{"id":"name","target":{"fromInput":"target"},"operation":"patch","set":{"name":{"fromInput":"value"}}}]}}],
        "accessProfiles":[{"id":"clerk","default":true,"principalClaim":"sub","requiredScopes":["proposal:manage"],
            "requiredPurposes":["registry-administration"],"permissions":{
                "records":[{"recordType":"target","operations":["create","get","list"],"readableFields":readable,
                    "writableFields":["name","status","capacity","jurisdiction"],
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}],
                "actions":[{"action":"correct-name","operations":["start"],"targets":[{"recordType":"target",
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}],
                "proposals":[{"action":"correct-name","operations":["get","list","edit","submit","revise","rebase","retry","cancel","apply"],
                    "ownership":"caller","targets":[{"recordType":"target",
                    "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}]}}]});
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).expect("guard project compiles")
}

/// A draft over a fresh target Record whose status is `status` and whose
/// capacity is `capacity`, asking for a minimum capacity of 5.
async fn draft(
    fixture: &client_http::ClientFixture,
    status: &str,
    capacity: i64,
    name: &str,
) -> (BRegProposal, String) {
    let client = &fixture.http.client;
    let metadata = client.registry_contract(Some("clerk")).await.unwrap();
    let BRegDirectWrite::Create(create) = metadata
        .value
        .select_direct_write("records.target.create", "clerk")
        .unwrap()
    else {
        panic!("create");
    };
    let record = client
        .create_record(
            &create,
            &BRegCreateRequest::new(map(
                json!({"name":"Before","status":status,"capacity":capacity,"jurisdiction":"zone-a"}),
            ))
            .unwrap(),
            &key(&format!("{name}-record")),
            BRegRecordFormat::Json,
        )
        .await
        .unwrap();
    let record_id = record.value.data.record_identifier.clone();
    let action = metadata
        .value
        .select_action("correct-name", "clerk")
        .unwrap();
    let input = BRegActionInvocationRequest::new(
        &action,
        map(json!({"target":record_id,"value":"After","minimum":5})),
        None,
    )
    .unwrap();
    let draft = client
        .start_proposal(&action, &input, &key(name))
        .await
        .unwrap()
        .value;
    (draft, record_id)
}

async fn set_status(fixture: &client_http::ClientFixture, record_id: &str, status: &str) {
    let entity = &fixture.registry.entities()["target"];
    fixture
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET \"{}\" = $2 WHERE record_id = $1::text::uuid",
                entity.physical_table, entity.fields["status"].physical_name
            ),
            &[&record_id, &status],
        )
        .await
        .unwrap();
}

async fn bump_revision(fixture: &client_http::ClientFixture, record_id: &str) {
    let entity = &fixture.registry.entities()["target"];
    fixture
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.\"{}\" SET record_revision = record_revision + 1 WHERE record_id = $1::text::uuid",
                entity.physical_table
            ),
            &[&record_id],
        )
        .await
        .unwrap();
}

async fn submit(
    fixture: &client_http::ClientFixture,
    draft: &BRegProposal,
    name: &str,
) -> Result<BRegProposal, registry_breg_client::BaseRegistryClientError> {
    let client = &fixture.http.client;
    let prepared = client
        .prepare_proposal(draft, "submit", json!({}), &key(name))
        .unwrap();
    client.execute_proposal(&prepared).await.map(|v| v.value)
}

async fn apply(
    fixture: &client_http::ClientFixture,
    submitted: &BRegProposal,
    name: &str,
) -> Result<BRegProposal, registry_breg_client::BaseRegistryClientError> {
    let client = &fixture.http.client;
    let prepared = client
        .prepare_proposal(
            submitted,
            "apply",
            json!({"submissionVersion":submitted.submission_version(),
                "effectDigest":submitted.effect_digest().unwrap()}),
            &key(name),
        )
        .unwrap();
    client.execute_proposal(&prepared).await.map(|v| v.value)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submit_names_a_failed_field_guard_when_the_profile_can_read_it() {
    let fixture = client_http::ClientFixture::start(
        registry(&["name", "status", "capacity", "jurisdiction"]),
        claims(),
    )
    .await;
    let (draft, _) = draft(&fixture, "retired", 10, "guard-submit").await;
    let refusal = submit(&fixture, &draft, "guard-submit-key")
        .await
        .unwrap_err();
    assert_eq!(
        refusal.problem_code(),
        Some(BRegProblemCode::ActionGuardFailed)
    );
    assert_eq!(refusal.guard_reason(), Some("target-not-open"));
    assert!(!format!("{refusal:?}").contains("retired"));
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apply_names_a_failed_field_guard_and_keeps_stale_revisions_generic() {
    let fixture = client_http::ClientFixture::start(
        registry(&["name", "status", "capacity", "jurisdiction"]),
        claims(),
    )
    .await;
    let (open, open_id) = draft(&fixture, "open", 10, "guard-apply").await;
    let submitted = submit(&fixture, &open, "guard-apply-submit").await.unwrap();
    set_status(&fixture, &open_id, "retired").await;
    let refusal = apply(&fixture, &submitted, "guard-apply-key")
        .await
        .unwrap_err();
    assert_eq!(
        refusal.problem_code(),
        Some(BRegProblemCode::ActionGuardFailed)
    );
    assert_eq!(refusal.guard_reason(), Some("target-not-open"));

    // A revision mismatch is concurrency, never a business-state refusal, even
    // while the guard would also fail.
    let (other, other_id) = draft(&fixture, "open", 10, "guard-stale").await;
    let submitted = submit(&fixture, &other, "guard-stale-submit")
        .await
        .unwrap();
    bump_revision(&fixture, &other_id).await;
    set_status(&fixture, &other_id, "retired").await;
    let stale = apply(&fixture, &submitted, "guard-stale-key")
        .await
        .unwrap_err();
    assert_eq!(
        stale.problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    assert_eq!(stale.guard_reason(), None);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submit_names_a_failed_input_comparison_guard() {
    let fixture = client_http::ClientFixture::start(
        registry(&["name", "status", "capacity", "jurisdiction"]),
        claims(),
    )
    .await;
    let (draft, _) = draft(&fixture, "open", 3, "guard-minimum").await;
    let refusal = submit(&fixture, &draft, "guard-minimum-key")
        .await
        .unwrap_err();
    assert_eq!(
        refusal.problem_code(),
        Some(BRegProblemCode::ActionGuardFailed)
    );
    assert_eq!(refusal.guard_reason(), Some("below-minimum"));
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_guard_field_stays_a_generic_precondition_refusal() {
    // The profile cannot read `status`, so naming the failed guard would
    // disclose a fact it cannot read.
    let fixture =
        client_http::ClientFixture::start(registry(&["name", "jurisdiction"]), claims()).await;
    let (draft, _) = draft(&fixture, "retired", 10, "guard-hidden").await;
    let refusal = submit(&fixture, &draft, "guard-hidden-key")
        .await
        .unwrap_err();
    assert_eq!(
        refusal.problem_code(),
        Some(BRegProblemCode::PreconditionFailed)
    );
    assert_eq!(refusal.guard_reason(), None);
    fixture.finish().await;
}
