// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::compiler::{compile_project, CompileProfile};
use crate::contract::parse_project_json;
use crate::request_workflow::{
    RequestKey, RequestWorkflow, TrustedActorRef, TrustedTimestamp, TrustedTransitionContext,
};
use serde_json::json;

const PACKAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TARGET: &str = "00000000-0000-4000-8000-000000000001";

fn fixture(effects: Value) -> CompiledRegistry {
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"request-preparation","version":"1","defaultLanguage":"en"},
        "entities":[{
            "id":"target","route":"targets","mutationMode":"mutable",
            "changeControl":{"requiredFor":["create","patch"]},
            "fields":[
                {"id":"first","type":"string","maxLength":64,"classification":"internal"},
                {"id":"second","type":"string","maxLength":64,"classification":"internal"},
                {"id":"parent","type":"reference","target":"target","classification":"internal"},
                {"id":"notes","type":"text","maxLength":1048576,"classification":"internal"}
            ]
        },{
            "id":"request","route":"requests","mutationMode":"mutable",
            "fields":[
                {"id":"one","type":"reference","target":"target","classification":"internal"},
                {"id":"two","type":"reference","target":"target","classification":"internal"},
                {"id":"value","type":"string","maxLength":64,"required":true,"classification":"internal"}
            ],
            "changeRequest":{"effects":effects,"review":{"stages":[{"id":"review","approvals":1}]}}
        }],
        "accessProfiles":[{"id":"submitter","default":true,"principalClaim":"sub","grants":[{
            "entity":"request","operations":["get","submit_request","approve_request","apply_request"],"readableFields":["one","two","value"],
            "reviewStages":[{"stage":"review","targets":[{"entity":"target","readableFields":["first","second","parent"]}]}],
            "applyTargets":[{"entity":"target"}]
        }]}]
    });
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).expect("preparation fixture compiles")
}

fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn existing(
    registry: &CompiledRegistry,
    intake: Map<String, Value>,
    before: Map<String, Value>,
) -> Result<PreparedRequest, MutationError> {
    let entity = &registry.entities()["request"];
    let resolved = resolve_targets(entity, &intake, &BTreeMap::new())?;
    prepare(
        registry,
        entity,
        &intake,
        1,
        PACKAGE,
        &resolved,
        BTreeMap::from([(
            ("target".to_owned(), Uuid::parse_str(TARGET).unwrap()),
            (7, before),
        )]),
    )
}

#[test]
fn aliased_effects_merge_disjoint_fields_and_refuse_overlapping_writes() {
    let effects = json!([
        {"target":{"fromField":"one"},"operation":"patch","set":{"first":{"fromField":"value"}}},
        {"target":{"fromField":"two"},"operation":"patch","clear":["second"]}
    ]);
    let registry = fixture(effects.clone());
    let intake = map(json!({"one":TARGET,"two":TARGET,"value":"changed"}));
    let before = map(json!({"first":"old","second":"old","notes":"preserved"}));
    let prepared = existing(&registry, intake.clone(), before.clone()).unwrap();
    assert_eq!(prepared.targets.len(), 1);
    assert_eq!(
        prepared.targets[0].after,
        map(json!({"first":"changed","second":null,"notes":"preserved"}))
    );
    assert_eq!(prepared.targets[0].expected_revision, Some(7));

    let mut overlap = effects;
    overlap[1]["clear"] = json!(["first"]);
    let registry = fixture(overlap);
    assert!(matches!(
        existing(&registry, intake, before),
        Err(MutationError::InvalidRequest)
    ));
}

#[test]
fn from_field_refuses_missing_null_and_wrong_type_without_partial_effects() {
    let registry = fixture(
        json!([{"target":{"fromField":"one"},"operation":"patch","set":{"first":{"fromField":"value"}}}]),
    );
    for intake in [
        json!({"one":TARGET}),
        json!({"one":TARGET,"value":null}),
        json!({"one":TARGET,"value":42}),
    ] {
        assert!(matches!(
            existing(&registry, map(intake), map(json!({"first":"old"}))),
            Err(MutationError::InvalidRequest)
        ));
    }
}

#[test]
fn unchanged_snapshot_bytes_count_toward_the_full_packet_limit() {
    let registry = fixture(
        json!([{"target":{"fromField":"one"},"operation":"patch","set":{"first":{"fromField":"value"}}}]),
    );
    let intake = map(json!({"one":TARGET,"value":"small"}));
    let before = map(json!({"first":"old","notes":"a".repeat(MAX_REQUEST_SNAPSHOT_BYTES / 2)}));
    assert!(matches!(
        existing(&registry, intake, before),
        Err(MutationError::InvalidRequest)
    ));
}

#[test]
fn create_references_reuse_reserved_ids_across_preparation_attempts() {
    let registry = fixture(json!([
        {"id":"parent","target":{"entity":"target"},"operation":"create","set":{"first":{"fromField":"value"}}},
        {"id":"child","target":{"entity":"target"},"operation":"create","set":{"parent":{"fromEffect":"parent"}}}
    ]));
    let entity = &registry.entities()["request"];
    let intake = map(json!({"value":"created"}));
    let reserved = BTreeMap::from([
        ("parent".to_owned(), Uuid::new_v4()),
        ("child".to_owned(), Uuid::new_v4()),
    ]);
    for _ in 0..3 {
        let resolved = resolve_targets(entity, &intake, &reserved).unwrap();
        let prepared = prepare(
            &registry,
            entity,
            &intake,
            1,
            PACKAGE,
            &resolved,
            BTreeMap::new(),
        )
        .unwrap();
        let child = prepared
            .targets
            .iter()
            .find(|target| target.record_id == reserved["child"])
            .unwrap();
        assert_eq!(child.after["parent"], reserved["parent"].to_string());
    }
}

#[test]
fn review_packet_refuses_extra_missing_or_altered_frozen_targets() {
    let registry = fixture(
        json!([{"target":{"fromField":"one"},"operation":"patch","set":{"first":{"fromField":"value"}}}]),
    );
    let prepared = existing(
        &registry,
        map(json!({"one":TARGET,"value":"approved"})),
        map(json!({"first":"old","second":"unchanged"})),
    )
    .unwrap();
    let owner = TrustedActorRef::from_verified_context("owner-reference").unwrap();
    let workflow = RequestWorkflow::new_draft(
        RequestKey::new(
            EntityId::new("request").unwrap(),
            RecordId::new(Uuid::new_v4().to_string()).unwrap(),
        ),
        owner.clone(),
        crate::request_workflow::StateRevision::new(1).unwrap(),
    );
    let workflow = workflow
        .submit(
            TrustedTransitionContext::from_verified_context(
                owner,
                TrustedTimestamp::from_server_clock("2026-08-31T00:00:00Z").unwrap(),
            ),
            prepared.proposal,
        )
        .unwrap()
        .into_workflow();
    let proposal = workflow.current_proposal().unwrap();
    let mut targets = prepared.targets;
    validate_frozen_targets(proposal, &targets).unwrap();
    assert!(validate_frozen_targets(proposal, &[]).is_err());
    targets[0]
        .after
        .insert("second".to_owned(), json!("unapproved"));
    assert!(validate_frozen_targets(proposal, &targets).is_err());
    targets[0]
        .after
        .insert("second".to_owned(), json!("unchanged"));
    targets[0].expected_revision = Some(8);
    assert!(validate_frozen_targets(proposal, &targets).is_err());
}
