// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use crate::contract::{parse_project_json, ModuleAssetSource};
use crate::request_workflow::{
    RequestKey, RequestWorkflow, TrustedActorRef, TrustedTimestamp, TrustedTransitionContext,
};
use serde_json::json;
use std::time::{Duration, Instant};

const PACKAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TARGET: &str = "00000000-0000-4000-8000-000000000001";

fn fixture(effects: Value) -> CompiledRegistry {
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"request-preparation","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
        "entities":[{
            "id":"target","primaryDataset":"test-dataset","route":"targets","mutationMode":"mutable",
            "changeControl":{"requiredFor":["create","patch"]},
            "fields":[
                {"id":"first","type":"string","maxLength":64,"classification":"internal"},
                {"id":"second","type":"string","maxLength":64,"classification":"internal"},
                {"id":"parent","type":"reference","target":"target","classification":"internal"},
                {"id":"notes","type":"text","maxLength":1048576,"classification":"internal"}
            ]
        },{
            "id":"request","primaryDataset":"test-dataset","route":"requests","mutationMode":"mutable",
            "fields":[
                {"id":"one","type":"reference","target":"target","classification":"internal"},
                {"id":"two","type":"reference","target":"target","classification":"internal"},
                {"id":"value","type":"string","maxLength":64,"required":true,"classification":"internal"}
            ],
            "changeRequest":{"effects":effects,"review":{"stages":[{"id":"review","approvals":1}]}}
        }],
        "accessProfiles":[{"id":"submitter","default":true,"principalClaim":"sub","grants":[{
            "entity":"request","operations":["get","submit_request","approve_request","apply_request"],"readableFields":["one","two","value"],
            "reviewStages":[{"stage":"review","targets":[{"entity":"target","readableFields":["first","second","parent"], "rowBoundaries": []}]}],
            "applyTargets":[{"entity":"target", "rowBoundaries": []}],
          "rowBoundaries": []
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
    let candidate = crate::rhai_planner::plan_change_request_effects(
        entity.change_request.as_ref().unwrap(),
        &intake,
        Instant::now() + Duration::from_secs(1),
    )
    .map_err(|_| MutationError::InvalidRequest)?;
    let resolved = resolve_targets(registry, entity, &intake, candidate, &BTreeMap::new())?;
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
fn declarative_and_rhai_paths_produce_byte_equivalent_canonical_effects() {
    let project = |change_request: Value| {
        json!({
            "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
            "registry":{"id":"request-differential","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
            "entities":[{
                "id":"target","primaryDataset":"test-dataset","route":"targets","mutationMode":"mutable",
                "changeControl":{"requiredFor":["patch"]},
                "fields":[{"id":"first","type":"string","maxLength":64,"classification":"internal"}]
            },{
                "id":"request","primaryDataset":"test-dataset","route":"requests","mutationMode":"mutable",
                "fields":[
                    {"id":"one","type":"reference","target":"target","required":true,"classification":"internal"},
                    {"id":"value","type":"string","maxLength":64,"required":true,"classification":"internal"}
                ],
                "changeRequest":change_request
            }],
            "accessProfiles":[{"id":"submitter","default":true,"principalClaim":"sub","grants":[{
                "entity":"request","operations":["get","submit_request","approve_request","apply_request"],
                "readableFields":["one","value"],
                "reviewStages":[{"stage":"review","targets":[{"entity":"target","readableFields":["first"], "rowBoundaries": []}]}],
                "applyTargets":[{"entity":"target", "rowBoundaries": []}],
              "rowBoundaries": []
            }]}]
        })
    };
    let review = json!({"stages":[{"id":"review","approvals":1}]});
    let declarative_source = project(json!({
        "effects":[{"target":{"fromField":"one"},"operation":"patch","set":{"first":{"fromField":"value"}}}],
        "review":review.clone()
    }));
    let declarative_project = parse_project_json(
        &serde_json::to_vec(&declarative_source).expect("declarative source serializes"),
    )
    .expect("declarative source parses");
    let declarative = compile_project(&declarative_project, &[], CompileProfile::Authoring)
        .expect("declarative source compiles");

    let rhai_source = project(json!({
        "planner":{
            "kind":"rhai",
            "script":"scripts/plan.rhai",
            "abi":"registry.change-request-plan/v1",
            "requestFields":["one","value"],
            "writes":[{"target":{"fromField":"one"},"operation":"patch","fields":["first"]}]
        },
        "review":review
    }));
    let rhai_project =
        parse_project_json(&serde_json::to_vec(&rhai_source).expect("Rhai source serializes"))
            .expect("Rhai source parses");
    let rhai = compile_project_with_assets(
        &rhai_project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "scripts/plan.rhai".to_owned(),
            bytes: br#"fn plan(ctx) { #{effects: [#{target: #{fromField: "one"}, operation: "patch", set: #{first: ctx.request.value}}]} }"#.to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .expect("Rhai source compiles");

    let intake = map(json!({"one":TARGET,"value":"changed"}));
    let before = map(json!({"first":"old"}));
    let prepare_with = |registry: &CompiledRegistry| {
        let request_entity = &registry.entities()["request"];
        let candidate = crate::rhai_planner::plan_change_request_effects(
            request_entity
                .change_request
                .as_ref()
                .expect("request plan exists"),
            &intake,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("planner produces candidate");
        let resolved = resolve_targets(
            registry,
            request_entity,
            &intake,
            candidate,
            &BTreeMap::new(),
        )
        .expect("candidate resolves through the shared verifier");
        prepare(
            registry,
            request_entity,
            &intake,
            1,
            PACKAGE,
            &resolved,
            BTreeMap::from([(
                ("target".to_owned(), Uuid::parse_str(TARGET).unwrap()),
                (7, before.clone()),
            )]),
        )
        .expect("candidate prepares through the shared canonical path")
    };
    let declarative = prepare_with(&declarative);
    let rhai = prepare_with(&rhai);
    let declarative_effects = canonicalize_json(
        &serde_json::to_value(declarative.proposal.effects()).expect("effects serialize"),
    )
    .expect("effects canonicalize");
    let rhai_effects = canonicalize_json(
        &serde_json::to_value(rhai.proposal.effects()).expect("effects serialize"),
    )
    .expect("effects canonicalize");
    assert_eq!(declarative_effects, rhai_effects);
    assert_eq!(declarative.targets.len(), 1);
    assert_eq!(rhai.targets.len(), 1);
    assert_eq!(declarative.targets[0].entity_id, rhai.targets[0].entity_id);
    assert_eq!(declarative.targets[0].record_id, rhai.targets[0].record_id);
    assert_eq!(declarative.targets[0].operation, rhai.targets[0].operation);
    assert_eq!(
        declarative.targets[0].expected_revision,
        rhai.targets[0].expected_revision
    );
    assert_eq!(declarative.targets[0].before, rhai.targets[0].before);
    assert_eq!(declarative.targets[0].after, rhai.targets[0].after);
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
        let candidate = crate::rhai_planner::plan_change_request_effects(
            entity.change_request.as_ref().unwrap(),
            &intake,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        let resolved = resolve_targets(&registry, entity, &intake, candidate, &reserved).unwrap();
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
fn candidate_dependency_cycles_are_refused_before_target_resolution() {
    let registry = fixture(json!([
        {"id":"parent","target":{"entity":"target"},"operation":"create","set":{"first":{"fromField":"value"}}},
        {"id":"child","target":{"entity":"target"},"operation":"create","set":{"parent":{"fromEffect":"parent"}}}
    ]));
    let entity = &registry.entities()["request"];
    let intake = map(json!({"value":"created"}));
    let mut candidate = crate::rhai_planner::plan_change_request_effects(
        entity.change_request.as_ref().unwrap(),
        &intake,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    candidate.effects[0].depends_on.insert("child".to_owned());
    assert!(matches!(
        resolve_targets(
            &registry,
            entity,
            &intake,
            candidate,
            &BTreeMap::from([
                ("parent".to_owned(), Uuid::new_v4()),
                ("child".to_owned(), Uuid::new_v4()),
            ]),
        ),
        Err(MutationError::InvalidRequest)
    ));
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

#[test]
fn rhai_planner_refuses_authority_ceiling_escape_before_target_locks() {
    let source = json!({
        "apiVersion":"registry.registrystack.org/v1alpha1", "kind":"RegistryProject",
        "registry":{"id":"planner-ceiling","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
        "entities":[{
            "id":"target","primaryDataset":"test-dataset","route":"targets","mutationMode":"mutable",
            "changeControl":{"requiredFor":["patch"]},
            "fields":[
                {"id":"allowed","type":"string","maxLength":64,"classification":"internal"},
                {"id":"forbidden","type":"string","maxLength":64,"classification":"internal"}
            ]
        },{
            "id":"request","primaryDataset":"test-dataset","route":"requests","mutationMode":"mutable",
            "fields":[
                {"id":"target-ref","type":"reference","target":"target","required":true,"classification":"internal"},
                {"id":"value","type":"string","maxLength":64,"required":true,"classification":"internal"}
            ],
            "changeRequest":{
                "planner":{
                    "kind":"rhai","script":"scripts/plan.rhai","abi":"registry.change-request-plan/v1",
                    "requestFields":["target-ref","value"],
                    "writes":[{"target":{"fromField":"target-ref"},"operation":"patch","fields":["allowed"]}]
                },
                "review":{"stages":[{"id":"review","approvals":1}]}
            }
        }],
        "accessProfiles":[{"id":"submitter","default":true,"principalClaim":"sub","grants":[{
            "entity":"request","operations":["get","submit_request","approve_request","apply_request"],
            "readableFields":["target-ref","value"],
            "reviewStages":[{"stage":"review","targets":[{"entity":"target","readableFields":["allowed"], "rowBoundaries": []}]}],
            "applyTargets":[{"entity":"target", "rowBoundaries": []}],
          "rowBoundaries": []
        }]}]
    });
    let project = parse_project_json(&serde_json::to_vec(&source).expect("source serializes"))
        .expect("source parses");
    let registry = compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "scripts/plan.rhai".to_owned(),
            bytes: br#"fn plan(ctx) { #{effects: [#{target: #{fromField: "target-ref"}, operation: "patch", set: #{allowed: ctx.request.value}}]} }"#.to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .expect("Rhai source compiles");
    let request_entity = &registry.entities()["request"];
    let intake = map(json!({"target-ref":TARGET,"value":"changed"}));
    let mut candidate = crate::rhai_planner::plan_change_request_effects(
        request_entity.change_request.as_ref().unwrap(),
        &intake,
        Instant::now() + Duration::from_secs(1),
    )
    .expect("bounded planner returns a candidate");
    match &mut candidate.effects[0].mutations[0] {
        crate::rhai_planner::CandidateChangeRequestMutation::Set { field, .. } => {
            *field = "forbidden".to_owned();
        }
        mutation => panic!("unexpected planner mutation: {mutation:?}"),
    }

    // resolve_targets is deliberately the shared, database-free verifier.
    // An escape is refused here, before any caller can acquire target locks.
    assert!(matches!(
        resolve_targets(
            &registry,
            request_entity,
            &intake,
            candidate,
            &BTreeMap::new(),
        ),
        Err(MutationError::InvalidRequest)
    ));
}
