// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::action_handler::{ActionHandlerOutcome, evaluate_plan_detailed};
use crate::compiler::{CompileProfile, compile_project_with_assets};
use crate::contract::{ModuleAssetSource, parse_project_json};
use crate::proposal_workflow::{
    ProposalKey, ProposalWorkflow, TrustedActorRef, TrustedTimestamp, TrustedTransitionContext,
};
use serde_json::json;
use std::time::{Duration, Instant};

const PACKAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TARGET: &str = "00000000-0000-4000-8000-000000000001";
const OTHER_TARGET: &str = "00000000-0000-4000-8000-000000000003";

fn patch_effect() -> Value {
    json!({"id":"patch-first","target":{"fromInput":"one"},"operation":"patch","set":{"first":{"fromInput":"value"}}})
}
fn source(effects: Value) -> Value {
    json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"proposal-preparation","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
        "datasets":[{"id":"records"}],
        "recordTypes":[{"id":"target","primaryDataset":"records","route":"targets","mutationMode":"mutable","mutationPolicy":{"create":"proposal-required","patch":"proposal-required"},"fields":[
            {"id":"first","type":"string","maximumLength":64,"classification":"internal"},
            {"id":"second","type":"string","maximumLength":64,"classification":"internal"},
            {"id":"parent","type":"reference","target":"target","classification":"internal"},
            {"id":"notes","type":"text","maximumLength":1048576,"classification":"internal"}
        ]}],
        "actions":[{"id":"change-target","execution":{"mode":"proposal","proposal":{"review":{"type":"none"},"application":{"mode":"manual"},"retention":{"mode":"retain"}}},"inputs":[
            {"id":"one","type":"reference","target":"target","classification":"internal"},
            {"id":"two","type":"reference","target":"target","classification":"internal"},
            {"id":"value","type":"string","maximumLength":64,"required":true,"classification":"internal"}
        ],"plan":{"type":"fixed","effects":effects}}],
        "accessProfiles":[{"id":"submitter","default":true,"principalClaim":"sub","requiredScopes":"unrestricted","permissions":{
            "actions":[{"action":"change-target","operations":["start"],"targets":[{"recordType":"target","rowBoundaries":"unrestricted"}]}],
            "proposals":[{"action":"change-target","operations":["get","submit","apply"],"ownership":"caller","targets":[{"recordType":"target","rowBoundaries":"unrestricted"}]}]
        }}]
    })
}
fn compile(source: Value, script: Option<&str>) -> CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    let assets = script
        .into_iter()
        .map(|script| ModuleAssetSource {
            module: None,
            path: "plans/change.rhai".into(),
            bytes: script.as_bytes().to_vec(),
        })
        .collect::<Vec<_>>();
    compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring)
        .expect("preparation fixture compiles")
}
fn fixture(effects: Value) -> CompiledRegistry {
    compile(source(effects), None)
}
fn fixture_with(effects: Value, customize: impl FnOnce(&mut Value)) -> CompiledRegistry {
    let mut value = source(effects);
    customize(&mut value);
    compile(value, None)
}
fn function_source() -> Value {
    let mut value = source(json!([patch_effect()]));
    value["actions"][0]["inputs"][0]["required"] = json!(true);
    value["functions"] = json!([{"id":"change-plan","runtime":"rhai","source":"plans/change.rhai","entrypoint":"plan","abi":"registry.action-plan/v1","capabilities":[]}]);
    value["actions"][0]["plan"] = json!({"type":"function","function":"change-plan","inputs":["one","value"],"writes":[{"id":"patch-first","target":{"fromInput":"one"},"operation":"patch","fields":["first"]}]});
    value
}
const SCRIPT: &str =
    r#"fn plan(ctx) { #{effects:[#{id:"patch-first",set:#{first:ctx.inputs.value}}]} }"#;
fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}
fn action(registry: &CompiledRegistry) -> &CompiledAction {
    &registry.actions().actions[0]
}
fn candidate(
    registry: &CompiledRegistry,
    input: &Map<String, Value>,
) -> Result<Vec<CompiledPlanEffect>, MutationError> {
    match evaluate_plan_detailed(
        action(registry),
        input,
        Instant::now() + Duration::from_secs(1),
    )
    .map_err(|_| MutationError::InvalidRequest)?
    {
        ActionHandlerOutcome::Effects(effects) => Ok(effects),
        _ => Err(MutationError::InvalidRequest),
    }
}
fn existing(
    registry: &CompiledRegistry,
    input: Map<String, Value>,
    before: Map<String, Value>,
) -> Result<PreparedProposalPlan, MutationError> {
    let resolved = resolve_targets(
        registry,
        action(registry),
        &input,
        candidate(registry, &input)?,
        &BTreeMap::new(),
    )?;
    prepare(
        registry,
        action(registry),
        &input,
        1,
        PACKAGE,
        &resolved,
        BTreeMap::from([(
            ("target".into(), Uuid::parse_str(TARGET).unwrap()),
            (7, before),
        )]),
        BTreeMap::new(),
    )
}

#[test]
fn neutral_inputs_preserve_omitted_and_function_null_distinction() {
    let mut value = function_source();
    value["actions"][0]["inputs"].as_array_mut().unwrap().push(json!({"id":"optional-note","type":"string","maximumLength":32,"classification":"internal"}));
    let registry = compile(value, Some(SCRIPT));
    for (input, present) in [
        (map(json!({"one":TARGET,"value":"changed"})), false),
        (
            map(json!({"one":TARGET,"value":"changed","optional-note":null,"two":null})),
            true,
        ),
    ] {
        let prepared = existing(&registry, input, map(json!({"first":"old"}))).unwrap();
        let frozen = serde_json::to_value(&prepared.proposal).unwrap();
        assert_eq!(frozen["inputs"].get("optional-note").is_some(), present);
        if present {
            assert_eq!(frozen["inputs"]["optional-note"], Value::Null);
        }
    }
    let fixed = fixture_with(json!([patch_effect()]), |source| {
        source["actions"][0]["inputs"].as_array_mut().unwrap().push(json!({"id":"optional-note","type":"string","maximumLength":32,"classification":"internal"}))
    });
    assert!(
        existing(
            &fixed,
            map(json!({"one":TARGET,"value":"changed","optional-note":null})),
            map(json!({"first":"old"}))
        )
        .is_err()
    );
}

#[test]
fn encrypted_participation_is_refused_before_targets_resolve() {
    // Untouched ciphertext remains legal in a target's retained snapshot.
    // A forged effect attempting to read or write outside the reviewed
    // plaintext ceiling must fail before target locks or materialization.
    let registry = fixture_with(json!([patch_effect()]), |source| {
        source["recordTypes"][0]["fields"].as_array_mut().unwrap().push(json!({"id":"secret","type":"string","maximumLength":64,"classification":"restricted","encrypted":true}))
    });
    let input = map(json!({"one":TARGET,"value":"changed"}));
    let legitimate = candidate(&registry, &input).unwrap();
    resolve_targets(
        &registry,
        action(&registry),
        &input,
        legitimate.clone(),
        &BTreeMap::new(),
    )
    .unwrap();
    for mutation in [
        CompiledPlanMutation::Set {
            field: "secret".into(),
            value: CompiledPlanValue::Literal {
                value: json!("sealed-canary"),
            },
        },
        CompiledPlanMutation::Clear {
            field: "secret".into(),
        },
        CompiledPlanMutation::Set {
            field: "first".into(),
            value: CompiledPlanValue::FromInput {
                input: "secret-value".into(),
            },
        },
    ] {
        let mut forged = legitimate.clone();
        forged[0].mutations = vec![mutation];
        assert!(matches!(
            resolve_targets(
                &registry,
                action(&registry),
                &input,
                forged,
                &BTreeMap::new()
            ),
            Err(MutationError::InvalidRequest)
        ));
    }
}

#[test]
fn preparation_requires_the_exact_guard_reference_snapshot_union() {
    let registry = fixture_with(json!([patch_effect()]), |source| {
        source["actions"][0]["inputs"].as_array_mut().unwrap().push(json!({"id":"guard-reference","type":"reference","target":"target","required":true,"classification":"internal"}));
        source["actions"][0]["commitGuards"] =
            json!({"targets":[{"input":"guard-reference","field":"first","equals":"changed"}]});
    });
    let input = map(json!({"one":TARGET,"value":"changed","guard-reference":OTHER_TARGET}));
    let resolved = resolve_targets(
        &registry,
        action(&registry),
        &input,
        candidate(&registry, &input).unwrap(),
        &BTreeMap::new(),
    )
    .unwrap();
    let run = |guards| {
        prepare(
            &registry,
            action(&registry),
            &input,
            1,
            PACKAGE,
            &resolved,
            BTreeMap::from([(
                ("target".into(), Uuid::parse_str(TARGET).unwrap()),
                (7, map(json!({"first":"old"}))),
            )]),
            guards,
        )
    };
    let correct = BTreeMap::from([(
        "guard-reference".into(),
        (
            Uuid::parse_str(OTHER_TARGET).unwrap(),
            4,
            map(json!({"first":"changed"})),
        ),
    )]);
    assert!(run(correct.clone()).is_ok());
    assert!(run(BTreeMap::new()).is_err());
    let mut wrong = correct.clone();
    wrong.get_mut("guard-reference").unwrap().0 = Uuid::parse_str(TARGET).unwrap();
    assert!(run(wrong).is_err());
    let mut extra = correct;
    extra.insert("undeclared".into(), (Uuid::new_v4(), 1, Map::new()));
    assert!(run(extra).is_err());
}

#[test]
fn aliased_effects_merge_disjoint_fields_and_refuse_overlapping_writes() {
    let effects = json!([patch_effect(),{"id":"clear-second","target":{"fromInput":"two"},"operation":"patch","clear":["second"]}]);
    let registry = fixture(effects.clone());
    let input = map(json!({"one":TARGET,"two":TARGET,"value":"changed"}));
    let before = map(json!({"first":"old","second":"old","notes":"preserved"}));
    let prepared = existing(&registry, input.clone(), before.clone()).unwrap();
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
        existing(&registry, input, before),
        Err(MutationError::InvalidRequest)
    ));
}

#[test]
fn from_input_refuses_missing_null_and_wrong_type_without_partial_effects() {
    let registry = fixture(json!([patch_effect()]));
    for input in [
        json!({"one":TARGET}),
        json!({"one":TARGET,"value":null}),
        json!({"one":TARGET,"value":42}),
    ] {
        assert!(matches!(
            existing(&registry, map(input), map(json!({"first":"old"}))),
            Err(MutationError::InvalidRequest)
        ));
    }
}

#[test]
fn fixed_and_rhai_plans_produce_byte_equivalent_canonical_effects() {
    let fixed = fixture(json!([patch_effect()]));
    let rhai = compile(function_source(), Some(SCRIPT));
    let input = map(json!({"one":TARGET,"value":"changed"}));
    let before = map(json!({"first":"old"}));
    let fixed = existing(&fixed, input.clone(), before.clone()).unwrap();
    let rhai = existing(&rhai, input, before).unwrap();
    assert_eq!(
        canonicalize_json(&serde_json::to_value(fixed.proposal.effects()).unwrap()).unwrap(),
        canonicalize_json(&serde_json::to_value(rhai.proposal.effects()).unwrap()).unwrap()
    );
    assert_eq!(fixed.targets.len(), 1);
    assert_eq!(rhai.targets.len(), 1);
    let (a, b) = (&fixed.targets[0], &rhai.targets[0]);
    assert_eq!(a.entity_id, b.entity_id);
    assert_eq!(a.record_id, b.record_id);
    assert_eq!(a.operation, b.operation);
    assert_eq!(a.expected_revision, b.expected_revision);
    assert_eq!(a.before, b.before);
    assert_eq!(a.after, b.after);
}

#[test]
fn unchanged_snapshot_bytes_count_toward_the_full_packet_limit() {
    let registry = fixture(json!([patch_effect()]));
    let before = map(json!({"first":"old","notes":"a".repeat(MAX_PROPOSAL_SNAPSHOT_BYTES/2)}));
    assert!(matches!(
        existing(
            &registry,
            map(json!({"one":TARGET,"value":"small"})),
            before
        ),
        Err(MutationError::InvalidRequest)
    ));
}

#[test]
fn unchanged_encrypted_members_fit_the_stored_packet_expansion_budget() {
    const ENCRYPTED_FIELDS: usize = 48;
    const PLAINTEXT_BYTES_PER_FIELD: usize = 16 * 1024;
    const ENVELOPE_FIXED_BYTES: usize = 33;
    const MAX_ENVELOPE_MEMBER_OVERHEAD: usize = 72;
    let registry = fixture_with(json!([patch_effect()]), |source| {
        source["recordTypes"][0]["fields"].as_array_mut().unwrap().extend((0..ENCRYPTED_FIELDS).map(|index|json!({"id":format!("secret-{index}"),"type":"string","maximumLength":PLAINTEXT_BYTES_PER_FIELD,"classification":"restricted","encrypted":true})))
    });
    let base64_bytes = 4 * (PLAINTEXT_BYTES_PER_FIELD + ENVELOPE_FIXED_BYTES).div_ceil(3);
    let envelope = json!({crate::history_schema::ENVELOPE_MEMBER_TAG:"A".repeat(base64_bytes)});
    let mut before = map(json!({"first":"old"}));
    for index in 0..ENCRYPTED_FIELDS {
        before.insert(format!("secret-{index}"), envelope.clone());
    }
    let prepared = existing(
        &registry,
        map(json!({"one":TARGET,"value":"changed"})),
        before,
    )
    .expect("plaintext-only effects retain unchanged ciphertext snapshots");
    assert!(
        prepared.proposal.combined_snapshot_bytes() > crate::plan::MAX_PLAN_SNAPSHOT_BYTES as usize
    );
    assert!(prepared.proposal.combined_snapshot_bytes() <= MAX_PROPOSAL_SNAPSHOT_BYTES);
    assert_eq!(prepared.targets[0].after["first"], json!("changed"));
    assert_eq!(prepared.targets[0].after["secret-0"], envelope);
    let maximum_encrypted_members = 2
        * crate::proposal_workflow::MAX_PROPOSAL_TARGETS
        * crate::contract::MAX_ENCRYPTED_FIELDS_PER_ENTITY;
    let worst_case_expanded = 4 * (crate::plan::MAX_PLAN_SNAPSHOT_BYTES as usize).div_ceil(3)
        + maximum_encrypted_members * MAX_ENVELOPE_MEMBER_OVERHEAD;
    assert!(worst_case_expanded <= MAX_PROPOSAL_SNAPSHOT_BYTES);
}

fn create_effects() -> Value {
    json!([
        {"id":"parent","target":{"recordType":"target"},"operation":"create","set":{"first":{"fromInput":"value"}}},
        {"id":"child","target":{"recordType":"target"},"operation":"create","set":{"parent":{"fromEffect":"parent"}}}
    ])
}
#[test]
fn create_references_reuse_reserved_ids_across_preparation_attempts() {
    let registry = fixture(create_effects());
    let input = map(json!({"value":"created"}));
    let reserved = BTreeMap::from([
        ("parent".into(), Uuid::new_v4()),
        ("child".into(), Uuid::new_v4()),
    ]);
    for _ in 0..3 {
        let resolved = resolve_targets(
            &registry,
            action(&registry),
            &input,
            candidate(&registry, &input).unwrap(),
            &reserved,
        )
        .unwrap();
        let prepared = prepare(
            &registry,
            action(&registry),
            &input,
            1,
            PACKAGE,
            &resolved,
            BTreeMap::new(),
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
    let registry = fixture(create_effects());
    let input = map(json!({"value":"created"}));
    let mut effects = candidate(&registry, &input).unwrap();
    effects[0].depends_on.insert("child".into());
    assert!(matches!(
        resolve_targets(
            &registry,
            action(&registry),
            &input,
            effects,
            &BTreeMap::from([
                ("parent".into(), Uuid::new_v4()),
                ("child".into(), Uuid::new_v4())
            ])
        ),
        Err(MutationError::InvalidRequest)
    ));
}
#[test]
fn review_packet_refuses_extra_missing_or_altered_frozen_targets() {
    let registry = fixture(json!([patch_effect()]));
    let prepared = existing(
        &registry,
        map(json!({"one":TARGET,"value":"approved"})),
        map(json!({"first":"old","second":"unchanged"})),
    )
    .unwrap();
    let owner = TrustedActorRef::from_verified_context("owner-reference").unwrap();
    let workflow = ProposalWorkflow::new_draft(
        ProposalKey::new(
            EntityId::new("change-target").unwrap(),
            RecordId::new(Uuid::new_v4().to_string()).unwrap(),
        ),
        owner.clone(),
        crate::proposal_workflow::StateRevision::new(1).unwrap(),
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
    let mut extra = targets.clone();
    extra.push(targets[0].clone());
    assert!(validate_frozen_targets(proposal, &extra).is_err());
    targets[0]
        .after
        .insert("second".into(), json!("unapproved"));
    assert!(validate_frozen_targets(proposal, &targets).is_err());
    targets[0].after.insert("second".into(), json!("unchanged"));
    targets[0].expected_revision = Some(8);
    assert!(validate_frozen_targets(proposal, &targets).is_err());
}
#[test]
fn rhai_plan_refuses_authority_ceiling_escape_before_target_locks() {
    let registry = compile(function_source(), Some(SCRIPT));
    let input = map(json!({"one":TARGET,"value":"changed"}));
    let mut effects = candidate(&registry, &input).unwrap();
    match &mut effects[0].mutations[0] {
        CompiledPlanMutation::Set { field, .. } => *field = "second".into(),
        mutation => panic!("unexpected mutation {mutation:?}"),
    };
    assert!(matches!(
        resolve_targets(
            &registry,
            action(&registry),
            &input,
            effects,
            &BTreeMap::new()
        ),
        Err(MutationError::InvalidRequest)
    ));
}
