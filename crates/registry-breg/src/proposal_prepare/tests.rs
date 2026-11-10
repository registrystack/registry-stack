// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::action_handler::{evaluate_plan_detailed, ActionHandlerOutcome};
use crate::compiler::{compile_project_with_assets, CompileProfile};
use crate::contract::{parse_project_json, ModuleAssetSource};
use crate::proposal_workflow::{
    ProposalKey, ProposalWorkflow, TrustedActorRef, TrustedTimestamp, TrustedTransitionContext,
};
use serde_json::json;
use std::time::{Duration, Instant};

const ACTIVATION_ID: &str = "3b0c7a52-5d1e-4f6a-8b9c-0d1e2f3a4b01";
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
        None,
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
        ACTIVATION_ID,
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
    assert!(existing(
        &fixed,
        map(json!({"one":TARGET,"value":"changed","optional-note":null})),
        map(json!({"first":"old"}))
    )
    .is_err());
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
            ACTIVATION_ID,
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
fn proposal_preparation_freezes_the_date_computed_at_submission() {
    let mut source = function_source();
    source["project"]["timezone"] = json!("UTC");
    let script = r#"fn plan(ctx) { #{effects:[#{id:"patch-first",set:#{first:today()}}]} }"#;
    let registry = compile(source, Some(script));
    let input = map(json!({"one":TARGET,"value":"ignored"}));
    let effects = match evaluate_plan_detailed(
        action(&registry),
        &input,
        Some(time::macros::date!(2026 - 01 - 31)),
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap()
    {
        ActionHandlerOutcome::Effects(effects) => effects,
        ActionHandlerOutcome::Refusal(_) => panic!("effects expected"),
    };
    let resolved = resolve_targets(
        &registry,
        action(&registry),
        &input,
        effects,
        &BTreeMap::new(),
    )
    .unwrap();
    let prepared = prepare(
        &registry,
        action(&registry),
        &input,
        1,
        ACTIVATION_ID,
        &resolved,
        BTreeMap::from([(
            ("target".into(), Uuid::parse_str(TARGET).unwrap()),
            (7, map(json!({"first":"old"}))),
        )]),
        BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(prepared.targets[0].after["first"], json!("2026-01-31"));

    let later = evaluate_plan_detailed(
        action(&registry),
        &input,
        Some(time::macros::date!(2026 - 02 - 01)),
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    let ActionHandlerOutcome::Effects(later) = later else {
        panic!("effects expected")
    };
    assert_ne!(
        serde_json::to_value(prepared.proposal.effects()).unwrap(),
        serde_json::to_value(later).unwrap()
    );
    assert_eq!(
        prepared.targets[0].after["first"],
        json!("2026-01-31"),
        "the retained proposal plan is not recomputed for replay or Apply"
    );
}

#[test]
fn today_is_available_to_a_plan_the_call_detector_cannot_see() {
    // The function name is computed, so the metadata scan does not mark the
    // handler as using today(); the host still answers the call.
    let script = r#"fn plan(ctx) {
        let name = "to" + "day";
        let helper = Fn(name);
        #{effects:[#{id:"patch-first",set:#{first:helper.call()}}]}
    }"#;
    let now = time::macros::datetime!(2026-01-31 12:00 UTC);
    let input = map(json!({"one":TARGET,"value":"ignored"}));

    let mut with_zone = function_source();
    with_zone["project"]["timezone"] = json!("UTC");
    let registry = compile(with_zone, Some(script));
    assert!(!action(&registry).handler.as_ref().unwrap().uses_today);
    let date =
        crate::action_handler::trusted_evaluation_date(action(&registry), &registry, now).unwrap();
    assert_eq!(date, Some(time::macros::date!(2026 - 01 - 31)));
    let ActionHandlerOutcome::Effects(effects) = evaluate_plan_detailed(
        action(&registry),
        &input,
        date,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap() else {
        panic!("effects expected")
    };
    let effects = serde_json::to_string(&effects).unwrap();
    assert!(effects.contains("2026-01-31"), "{effects}");

    // Without a declared zone nothing answers today().
    let registry = compile(function_source(), Some(script));
    assert_eq!(
        crate::action_handler::trusted_evaluation_date(action(&registry), &registry, now).unwrap(),
        None
    );
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
            ACTIVATION_ID,
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

/// Links `target.first` to an external subject, so a value written there must
/// be a key the view can send to its source.
fn link_first(source: &mut Value) {
    source["externalRecordTypes"] = json!([{
        "id":"external-subject","authority":"urn:example:source","identifierScheme":"urn:example:subject-key",
        "fields":[{"id":"label","type":"string","classification":"internal"}]
    }]);
    source["externalProjections"] = json!([{
        "id":"approved-subjects","recordType":"external-subject","operation":"subjects-by-key","operationVersion":"1",
        "purpose":"local-consultation","scope":"approved-subjects","selectorScheme":"urn:example:subject-key",
        "mode":"indexed","cardinality":"one","cacheTtlSeconds":600,"fields":["label"]
    }]);
    source["externalViews"] = json!([{
        "id":"target-with-subject","recordType":"target",
        "links":[{"id":"subject","projection":"approved-subjects","fromField":"first",
            "identifierScheme":"urn:example:subject-key","fields":["label"]}]
    }]);
}

const MALFORMED_KEYS: [&str; 3] = [" padded", "trailing ", "bell\u{7}key"];

#[test]
fn a_malformed_link_key_is_refused_when_a_patch_proposal_is_prepared() {
    let linked = fixture_with(json!([patch_effect()]), link_first);
    let unlinked = fixture(json!([patch_effect()]));
    for malformed in MALFORMED_KEYS {
        let input = map(json!({"one":TARGET,"value":malformed}));
        assert!(
            matches!(
                existing(&linked, input.clone(), map(json!({"first":"old"}))),
                Err(MutationError::InvalidRequest)
            ),
            "{malformed:?} is refused on the linked field"
        );
        existing(&unlinked, input, map(json!({"first":"old"})))
            .expect("the same value is accepted on an unlinked field");
    }
    existing(
        &linked,
        map(json!({"one":TARGET,"value":"key-1"})),
        map(json!({"first":"old"})),
    )
    .expect("a well-formed key is accepted on the linked field");
}

#[test]
fn a_malformed_link_key_is_refused_when_a_create_proposal_is_prepared() {
    let linked = fixture_with(create_effects(), link_first);
    let unlinked = fixture(create_effects());
    let reserved = BTreeMap::from([
        ("parent".into(), Uuid::new_v4()),
        ("child".into(), Uuid::new_v4()),
    ]);
    for malformed in MALFORMED_KEYS {
        let input = map(json!({"value":malformed}));
        for (registry, accepted) in [(&linked, false), (&unlinked, true)] {
            let resolved = resolve_targets(
                registry,
                action(registry),
                &input,
                candidate(registry, &input).unwrap(),
                &reserved,
            )
            .unwrap();
            assert_eq!(
                materialize_create_fields(registry, &input, &resolved).is_ok(),
                accepted,
                "{malformed:?} on a create"
            );
        }
    }
}
