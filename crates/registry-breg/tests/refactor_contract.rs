// SPDX-License-Identifier: Apache-2.0
use registry_breg::{
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_yaml, ModuleAssetSource, RegistryProject},
    model::{CompiledActionExecution, CompiledPlanValue, CompiledProposalReview},
};
const MINIMAL: &[u8] =
    include_bytes!("../../../products/breg/examples/refactor/minimal/registry.yaml");
const PROJECT: &[u8] =
    include_bytes!("../../../products/breg/examples/refactor/facility/registry.yaml");
const FUNCTION: &[u8] =
    include_bytes!("../../../products/breg/examples/refactor/facility/plans/correct-address.rhai");
fn project_source() -> serde_json::Value {
    registry_platform_yaml::Reader::new("registry.yaml")
        .scan(PROJECT)
        .expect("canonical fixture uses the supported YAML subset")
        .expect("canonical fixture is nonempty")
        .to_json_value()
}
fn compile(
    project: &RegistryProject,
) -> Result<registry_breg::model::CompiledRegistry, registry_breg::diagnostics::CompileFailure> {
    compile_project_with_assets(
        project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/correct-address.rhai".into(),
            bytes: FUNCTION.to_vec(),
        }],
        CompileProfile::Authoring,
    )
}
#[test]
fn standalone_native_records_need_no_manifest_or_external_products() {
    let project = parse_project_yaml(MINIMAL).expect("minimal project reads");
    let model = compile(&project).expect("minimal standalone project compiles");
    assert!(model.manifest_projection().is_none());
    assert!(model.actions().actions.is_empty());
    assert!(!model.ddl().script().contains("registry_request_"));
    assert_eq!(model.entities()["contact"].api_name, "Contact");
    assert_eq!(
        model.entities()["contact"].display.label.as_deref(),
        Some("Contact")
    );
}
#[test]
fn one_action_family_compiles_both_modes_and_a_neutral_dag() {
    let project = parse_project_yaml(PROJECT).expect("canonical project reads");
    let model = compile(&project).expect("canonical project compiles");
    assert!(!serde_json::to_value(model.entities())
        .unwrap()
        .to_string()
        .contains("changeRequest"));
    assert!(!model.ddl().script().contains("registry_request_"));
    let actions = &model.actions().actions;
    let register = actions
        .iter()
        .find(|action| action.id == "register-facility")
        .unwrap();
    assert!(matches!(
        register.execution,
        CompiledActionExecution::Immediate
    ));
    assert_eq!(
        register
            .effects
            .iter()
            .map(|effect| effect.id.as_str())
            .collect::<Vec<_>>(),
        vec!["facility", "assignment"]
    );
    assert!(register.effects[1].depends_on.contains("facility"));
    assert!(register.effects[0]
        .mutations
        .iter()
        .any(|mutation| matches!(
            mutation,
            registry_breg::model::CompiledPlanMutation::Set {
                value: CompiledPlanValue::Literal { .. },
                ..
            }
        )));
    let correction = actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    let function = correction.handler.as_ref().unwrap();
    assert_eq!(function.entrypoint, "plan");
    assert_eq!(function.abi, "registry.action-plan/v1");
    assert_eq!(function.id, "correct-address-plan");
    let CompiledActionExecution::Proposal { proposal } = &correction.execution else {
        panic!("proposal execution")
    };
    assert!(matches!(
        proposal.review,
        CompiledProposalReview::Required { .. }
    ));
    let deactivate = actions
        .iter()
        .find(|action| action.id == "deactivate-facility")
        .unwrap();
    let CompiledActionExecution::Proposal { proposal } = &deactivate.execution else {
        panic!("proposal execution")
    };
    assert!(matches!(proposal.review, CompiledProposalReview::None));
    assert!(deactivate
        .requires
        .iter()
        .any(|guard| guard.revision_unchanged));
}

#[test]
fn canonical_address_function_evaluates_valid_inputs_and_declared_refusal() {
    use registry_breg::action_handler::{evaluate_action, ActionHandlerOutcome};
    use serde_json::json;
    let registry = compile(&parse_project_yaml(PROJECT).unwrap()).unwrap();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    let mut inputs=json!({"facility":"00000000-0000-4000-8000-000000000001","address-line":"1 Main Road","city":"Bangkok","postal-code":"10200"}).as_object().unwrap().clone();
    let outcome = evaluate_action(
        action,
        &inputs,
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    )
    .unwrap();
    let ActionHandlerOutcome::Effects(effects) = outcome else {
        panic!("valid address plan")
    };
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].id, "facility-address");
    assert_eq!(effects[0].mutations.len(), 3);
    inputs.insert("postal-code".into(), json!("   "));
    let outcome = evaluate_action(
        action,
        &inputs,
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    )
    .unwrap();
    let ActionHandlerOutcome::Refusal(refusal) = outcome else {
        panic!("blank postal code refusal")
    };
    assert_eq!(refusal.code, "invalid-postal-code");
    assert_eq!(refusal.field.as_deref(), Some("postal-code"));
}

#[test]
fn automatic_recovery_grants_reject_known_nonhuman_profiles() {
    use registry_breg::contract::parse_project_json;
    use serde_json::json;

    for (actor_kind, admitted) in [
        (None, true),
        (Some("human"), true),
        (Some("service"), false),
        (Some("agent"), false),
    ] {
        for operation in ["apply", "retry"] {
            let mut source = project_source();
            let profile = source["accessProfiles"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|profile| profile["id"] == "facility-correction-applier")
                .unwrap();
            if let Some(kind) = actor_kind {
                profile["actorKind"] = json!(kind);
                profile["requesterClients"] = json!(["registry-client"]);
            }
            let grant = profile["permissions"]["proposals"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|grant| grant["action"] == "correct-address")
                .unwrap();
            grant["operations"] = json!(["get", operation]);
            let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
            let result = compile(&project);
            if admitted {
                assert!(result.is_ok(), "{actor_kind:?}/{operation}: {result:?}");
            } else {
                assert!(
                    result.unwrap_err().diagnostics().iter().any(|diagnostic| {
                        diagnostic.code == "breg.proposal.automatic-recovery-requires-human"
                    }),
                    "{actor_kind:?}/{operation}"
                );
            }
        }
    }

    let mut source = project_source();
    let profile = source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["id"] == "facility-correction-applier")
        .unwrap();
    profile["actorKind"] = json!("service");
    profile["requesterClients"] = json!(["registry-client"]);
    profile["permissions"]["proposals"]
        .as_array_mut()
        .unwrap()
        .retain(|grant| grant["action"] == "deactivate-facility");
    let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
    assert!(
        compile(&project).is_ok(),
        "manual Apply keeps its own grant policy"
    );
}
#[test]
fn authored_after_is_not_a_plan_surface() {
    let original = std::str::from_utf8(PROJECT).unwrap();
    for dependency in ["assignment", "missing"] {
        let source = original.replace(
            "- id: facility\n          target:",
            &format!("- id: facility\n          after: [{dependency}]\n          target:"),
        );
        assert!(parse_project_yaml(source.as_bytes()).is_err());
    }
}

#[test]
fn proposal_attachments_require_explicit_bounded_slot_grants() {
    use registry_breg::contract::parse_project_json;
    use serde_json::json;
    let mut value: serde_json::Value = project_source();
    let action_index = value["actions"]
        .as_array()
        .unwrap()
        .iter()
        .position(|action| action["id"] == "correct-address")
        .unwrap();
    value["actions"][action_index]["execution"]["proposal"]["attachments"] = json!([{"id":"supporting-file","required":false,"maximumBytes":1024,"contentTypes":["application/pdf"],"classification":"restricted"}]);
    let profile_index = value["accessProfiles"]
        .as_array()
        .unwrap()
        .iter()
        .position(|profile| profile["id"] == "facility-correction-author")
        .unwrap();
    let grant = &mut value["accessProfiles"][profile_index]["permissions"]["proposals"][0];
    grant["readableAttachments"] = json!(["supporting-file"]);
    grant["writableAttachments"] = json!(["supporting-file"]);
    let model =
        compile(&parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap();
    let action = model
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    assert!(action.condition_route.is_none());
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        panic!("Proposal")
    };
    assert_eq!(proposal.attachments["supporting-file"].maximum_bytes, 1024);
    assert!(proposal
        .permissions
        .iter()
        .find(|permission| permission.profile_id == "facility-correction-author")
        .unwrap()
        .writable_attachments
        .contains("supporting-file"));
    let mut missing_operation = value.clone();
    missing_operation["accessProfiles"][profile_index]["permissions"]["proposals"][0]["operations"]
        .as_array_mut()
        .unwrap()
        .retain(|operation| operation != "edit");
    assert!(compile(
        &parse_project_json(&serde_json::to_vec(&missing_operation).unwrap()).unwrap()
    )
    .is_err());
    value["actions"][action_index]["execution"]["proposal"]["attachments"][0]["maximumBytes"] =
        json!(16777217);
    assert!(parse_project_json(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn explicit_automatic_application_has_a_bounded_revision_bound_system_grant() {
    use registry_breg::contract::parse_project_json;
    use serde_json::json;
    let mut value: serde_json::Value = project_source();
    let index = value["actions"]
        .as_array()
        .unwrap()
        .iter()
        .position(|action| action["id"] == "deactivate-facility")
        .unwrap();
    value["actions"][index]["execution"]["proposal"]["application"] =
        json!({"mode":"automatic","maximumAttempts":3});
    let model =
        compile(&parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap();
    let mut obsolete = value.clone();
    obsolete["actions"][index]["execution"]["proposal"]["application"]["executor"] =
        json!("self-http-executor");
    assert!(
        parse_project_json(&serde_json::to_vec(&obsolete).unwrap()).is_err(),
        "authored executor bindings are retired"
    );
    let action = model
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "deactivate-facility")
        .unwrap();
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        panic!("Proposal")
    };
    let grant = proposal.system_apply_grant.as_ref().unwrap();
    assert_eq!(grant.action_id, action.id);
    assert_eq!(grant.action_revision, action.definition_revision);
    assert_eq!(
        grant
            .targets
            .iter()
            .filter(|target| target.operation == registry_breg::contract::Operation::Patch)
            .count(),
        1
    );
    assert!(grant
        .targets
        .iter()
        .all(|target| target.entity_id == "facility"));
    assert_eq!(
        grant
            .targets
            .iter()
            .find(|target| target.operation == registry_breg::contract::Operation::Patch)
            .unwrap()
            .fields,
        std::collections::BTreeSet::from(["status".to_owned()])
    );
    for action in value["actions"].as_array_mut().unwrap() {
        if action["execution"]["mode"] == "proposal" {
            action["execution"]["proposal"]["application"] = json!({"mode":"manual"});
        }
    }
    let manual =
        compile(&parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap();
    assert!(manual
        .actions()
        .actions
        .iter()
        .all(|action| match &action.execution {
            CompiledActionExecution::Immediate => true,
            CompiledActionExecution::Proposal { proposal } => proposal.system_apply_grant.is_none(),
        }));
}

#[test]
fn generated_policy_names_fit_postgres_without_truncation_or_collisions() {
    use registry_breg::contract::parse_project_json;
    use serde_json::json;
    for automatic in [false, true] {
        let mut source: serde_json::Value = project_source();
        if automatic {
            for action in source["actions"].as_array_mut().unwrap() {
                if action["execution"]["mode"] == "proposal" {
                    action["execution"]["proposal"]["application"] =
                        json!({"mode":"automatic","maximumAttempts":3});
                }
            }
        }
        let model =
            compile(&parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap()).unwrap();
        for table in &model.ddl().tables {
            let mut names = std::collections::BTreeSet::new();
            for policy in &table.policies {
                assert!(
                    policy.name.len() <= 63,
                    "policy identifier exceeds PostgreSQL bytes: {}",
                    policy.name
                );
                assert!(
                    names.insert(&policy.name),
                    "duplicate policy identifier: {}",
                    policy.name
                );
            }
        }
    }
}

#[test]
fn system_executor_profile_cannot_inherit_authored_record_grants() {
    use registry_breg::contract::parse_project_json;
    let mut value: serde_json::Value = project_source();
    value["accessProfiles"][0]["id"] = serde_json::json!("system-proposal-apply");
    let failure =
        compile(&parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap_err();
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.access-profile.system-id-reserved"));
}

#[test]
fn unused_reference_inputs_require_bounded_current_target_admission() {
    use registry_breg::contract::parse_project_json;
    use serde_json::json;
    let mut value: serde_json::Value = project_source();
    value["actions"][0]["inputs"].as_array_mut().unwrap().push(json!({"id":"audit-entry","type":"reference","target":"directory-entry","classification":"internal"}));
    assert!(compile(&parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()).is_err());
    let profile = value["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|profile| profile["id"] == "facility-registrar")
        .unwrap();
    profile["permissions"]["actions"][0]["targets"].as_array_mut().unwrap().push(json!({"recordType":"directory-entry","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}));
    let model =
        compile(&parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap();
    let action = model
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-facility")
        .unwrap();
    assert!(action.target_uses.iter().any(|use_| use_.operation == registry_breg::contract::Operation::Get && matches!(&use_.source, registry_breg::model::CompiledActionTargetUseSource::Input {input} if input == "audit-entry")));
}

#[test]
fn guard_only_revision_reads_share_one_condition_bound_reference_scope() {
    use registry_breg::contract::parse_project_json;
    use serde_json::json;
    let mut value: serde_json::Value = project_source();
    value["actions"][0]["commitGuards"]["targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({"input":"operator","revision":"unchanged"}));
    let model =
        compile(&parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap();
    let action = model
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-facility")
        .unwrap();
    let reads = action.target_uses.iter().filter(|use_| matches!(&use_.source, registry_breg::model::CompiledActionTargetUseSource::Input {input} if input == "operator") && matches!(use_.operation, registry_breg::contract::Operation::Get | registry_breg::contract::Operation::Invoke)).collect::<Vec<_>>();
    assert_eq!(reads.len(), 1);
    assert!(reads[0].condition_required);
    assert_eq!(
        reads[0].fields,
        std::collections::BTreeSet::from(["status".to_owned(), "jurisdiction".to_owned()])
    );
    assert!(action.condition_route.is_some());
    assert!(model
        .actions()
        .actions
        .iter()
        .filter(|action| action.execution.is_proposal())
        .all(|action| action.condition_route.is_none()));
}

#[test]
fn relationships_use_enforced_cardinality_and_reject_cross_type_name_collisions() {
    use registry_breg::contract::parse_project_json;
    use registry_breg::model::RelationshipCardinality;
    use serde_json::json;
    let mut value: serde_json::Value = project_source();
    let model =
        compile(&parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap();
    assert_eq!(
        model.entities()["facility-assignment"].relationships["facility"].cardinality,
        RelationshipCardinality::One
    );
    assert_eq!(
        model.entities()["facility"].relationships["assignments"].cardinality,
        RelationshipCardinality::Many
    );
    let assignment = value["recordTypes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|record| record["id"] == "facility-assignment")
        .unwrap();
    assignment["constraints"] = json!([{"type":"unique","fields":["facility"]}]);
    let model =
        compile(&parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap();
    assert_eq!(
        model.entities()["facility"].relationships["assignments"].cardinality,
        RelationshipCardinality::OptionalOne
    );
    let assignment = value["recordTypes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|record| record["id"] == "facility-assignment")
        .unwrap();
    assignment["fields"][0]["relationship"]["inverseName"] = json!("name");
    assert!(compile(&parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()).is_err());
}

#[test]
fn review_context_schema_has_exact_bytes_and_no_policy_digest_cycle() {
    use registry_breg::compiler::review_context::compile_schema;
    use registry_breg::contract::parse_project_json;
    use serde_json::json;
    let mut value: serde_json::Value = project_source();
    let baseline =
        compile(&parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap();
    let action = baseline
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    let schema = compile_schema(&baseline, action).unwrap().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&schema.bytes).unwrap(),
        schema.schema
    );
    assert_eq!(
        schema.schema["properties"]["proposedCity"]["maxLength"],
        json!(120)
    );
    assert!(schema.revision.starts_with("sha256:"));
    let action_index = value["actions"]
        .as_array()
        .unwrap()
        .iter()
        .position(|action| action["id"] == "correct-address")
        .unwrap();
    value["actions"][action_index]["execution"]["proposal"]["review"]["policy"]["digest"] =
        json!(format!("sha256:{}", "f".repeat(64)));
    let changed_policy =
        compile(&parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap();
    let changed_action = changed_policy
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    assert_ne!(
        action.definition_revision,
        changed_action.definition_revision
    );
    let same_schema = compile_schema(&changed_policy, changed_action)
        .unwrap()
        .unwrap();
    assert_eq!(schema.revision, same_schema.revision);
    assert_eq!(schema.digest, same_schema.digest);
    assert_eq!(schema.bytes, same_schema.bytes);
    let mut changed_disclosure = value.clone();
    let record = changed_disclosure["recordTypes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|record| record["id"] == "facility")
        .unwrap();
    let address = record["fields"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|field| field["id"] == "address-line")
        .unwrap();
    address["classification"] = json!("restricted");
    let changed_disclosure =
        compile(&parse_project_json(&serde_json::to_vec(&changed_disclosure).unwrap()).unwrap())
            .unwrap();
    let changed_action = changed_disclosure
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    let changed_schema = compile_schema(&changed_disclosure, changed_action)
        .unwrap()
        .unwrap();
    assert_ne!(schema.revision, changed_schema.revision);
    assert_ne!(schema.digest, changed_schema.digest);
    assert_eq!(
        changed_schema.schema["x-registry-review-context"]["classifications"]["currentAddressLine"],
        "restricted"
    );
    value["valueTypes"]["city"]["maximumLength"] = json!(121);
    let changed_type =
        compile(&parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap();
    let changed_action = changed_type
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    assert_ne!(
        schema.revision,
        compile_schema(&changed_type, changed_action)
            .unwrap()
            .unwrap()
            .revision
    );
}
#[test]
fn immediate_mode_cannot_bypass_target_proposal_policy() {
    let mut project = parse_project_yaml(PROJECT).unwrap();
    project
        .actions
        .iter_mut()
        .find(|action| action.id == "deactivate-facility")
        .unwrap()
        .execution = registry_breg::contract::ActionExecutionSource::Immediate {};
    for profile in &mut project.access_profiles {
        profile
            .permissions
            .proposals
            .retain(|grant| grant.action != "deactivate-facility");
        for grant in &mut profile.permissions.actions {
            if grant.action == "deactivate-facility" {
                grant.operations = [registry_breg::contract::Operation::Invoke].into();
            }
        }
    }
    let failure = compile(&project).expect_err("immediate policy bypass refuses");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.action.effect-controlled-target"));
}
#[test]
fn presentation_and_unrelated_record_changes_preserve_action_revision() {
    let source = std::str::from_utf8(PROJECT).unwrap();
    let before = compile(&parse_project_yaml(PROJECT).unwrap()).unwrap();
    let changed = source
        .replace("label: Register facility", "label: Add facility")
        .replace("maximumLength: 254", "maximumLength: 253");
    let after = compile(&parse_project_yaml(changed.as_bytes()).unwrap()).unwrap();
    for action in &before.actions().actions {
        let successor = after
            .actions()
            .actions
            .iter()
            .find(|other| other.id == action.id)
            .unwrap();
        assert_eq!(action.definition_revision, successor.definition_revision);
    }
}
#[test]
fn local_type_and_function_changes_change_dependent_revision() {
    let source = std::str::from_utf8(PROJECT).unwrap();
    let before = compile(&parse_project_yaml(PROJECT).unwrap()).unwrap();
    let changed = source.replace("maximumLength: 240", "maximumLength: 239");
    let after = compile(&parse_project_yaml(changed.as_bytes()).unwrap()).unwrap();
    let revision = |model: &registry_breg::model::CompiledRegistry| {
        model
            .actions()
            .actions
            .iter()
            .find(|action| action.id == "correct-address")
            .unwrap()
            .definition_revision
            .clone()
    };
    assert_ne!(revision(&before), revision(&after));
    let project = parse_project_yaml(PROJECT).unwrap();
    let changed = compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/correct-address.rhai".into(),
            bytes: [FUNCTION, b"\n// reviewed source change\n"].concat(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap();
    assert_ne!(revision(&before), revision(&changed));
}

#[test]
fn exact_permission_changes_do_not_change_the_action_behavior_revision() {
    use registry_breg::contract::parse_project_json;
    use serde_json::json;
    let before = compile(&parse_project_yaml(PROJECT).unwrap()).unwrap();
    let mut source: serde_json::Value = project_source();
    for profile in source["accessProfiles"].as_array_mut().unwrap() {
        if profile["id"] == "facility-registrar" {
            profile["requiredScopes"] = json!(["registry:facility:register:v2"]);
            profile["permissions"]["actions"][0]["results"] = json!(["facility"]);
        }
        if profile["id"] == "facility-correction-author" {
            profile["requiredScopes"] = json!(["registry:facility:correction:submit:v2"]);
        }
    }
    let after =
        compile(&parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap()).unwrap();
    for action in &before.actions().actions {
        let successor = after
            .actions()
            .actions
            .iter()
            .find(|other| other.id == action.id)
            .unwrap();
        assert_eq!(action.definition_revision, successor.definition_revision);
        if action.id == "register-facility" || action.id == "correct-address" {
            assert_ne!(
                action.permissions, successor.permissions,
                "current admission retains exact changed grants"
            );
        }
    }
}

#[test]
fn untouched_target_schema_is_part_of_a_patch_snapshot_revision() {
    use registry_breg::contract::parse_project_json;
    use serde_json::json;
    let before = compile(&parse_project_yaml(PROJECT).unwrap()).unwrap();
    let mut source: serde_json::Value = project_source();
    let facility = source["recordTypes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|record| record["id"] == "facility")
        .unwrap();
    facility["fields"].as_array_mut().unwrap().push(json!({"id":"retained-note","type":"string","maximumLength":50,"classification":"internal"}));
    let after =
        compile(&parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap()).unwrap();
    for id in ["correct-address", "deactivate-facility"] {
        let revision = |model: &registry_breg::CompiledRegistry| {
            model
                .actions()
                .actions
                .iter()
                .find(|action| action.id == id)
                .unwrap()
                .definition_revision
                .clone()
        };
        assert_ne!(
            revision(&before),
            revision(&after),
            "whole stored rows participate in Patch preparation and packet bounds"
        );
    }
}
#[test]
fn local_types_cannot_be_overridden_at_use_sites() {
    let source = std::str::from_utf8(PROJECT).unwrap().replace(
        "typeRef: postal-code, required:",
        "typeRef: postal-code, maximumLength: 8, required:",
    );
    assert!(parse_project_yaml(source.as_bytes()).is_err());
}
#[test]
fn retired_project_shapes_are_not_read() {
    let source = std::str::from_utf8(MINIMAL)
        .unwrap()
        .replace("v1alpha1", "v2alpha1");
    assert!(parse_project_yaml(source.as_bytes()).is_err());
    let source = std::str::from_utf8(MINIMAL)
        .unwrap()
        .replace("recordTypes:", "entities:");
    assert!(parse_project_yaml(source.as_bytes()).is_err());
}

#[test]
fn retired_request_authority_keys_are_rejected_in_record_and_module_profiles() {
    use registry_breg::contract::{parse_module_json, parse_project_json};
    use serde_json::json;
    for (key, retired) in [
        ("submitterTargets", json!(["facility"])),
        (
            "requestPresence",
            json!([{"requestType":"legacy","rowBoundaries":"unrestricted"}]),
        ),
        (
            "applyTargets",
            json!([{"entity":"facility","rowBoundaries":"unrestricted"}]),
        ),
        ("requestVisibility", json!("owner")),
        ("readableRequestFields", json!(["reason"])),
    ] {
        let mut project: serde_json::Value = project_source();
        project["accessProfiles"][0]["permissions"]["records"][0][key] = retired.clone();
        assert!(
            parse_project_json(&serde_json::to_vec(&project).unwrap()).is_err(),
            "retired record permission {key}"
        );
        let mut module = json!({"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"records","version":"1","recordTypes":[{"id":"record","primaryDataset":"records","route":"records","mutationMode":"mutable","fields":[{"id":"name","type":"string","maximumLength":32,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"sub","requiredScopes":"unrestricted","operations":["get"],"readableFields":["name"],"rowBoundaries":"unrestricted"}]}]});
        module["recordTypes"][0]["accessProfiles"][0][key] = retired;
        assert!(
            parse_module_json(&serde_json::to_vec(&module).unwrap()).is_err(),
            "retired module profile {key}"
        );
    }
}

#[cfg(feature = "schema")]
#[test]
fn canonical_projects_match_generated_authoring_schema() {
    let documents = registry_breg::schema::documents().unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(&documents[registry_breg::schema::REGISTRY_PROJECT_SCHEMA_FILE])
            .unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("authoring schema compiles");
    for source in [MINIMAL, PROJECT] {
        let decoded = registry_platform_yaml::Reader::new("registry.yaml")
            .decode::<serde_json::Value>(
                source,
                &registry_platform_yaml::Expect::one(&registry_breg::contract::PROJECT_FORMAT),
            )
            .unwrap();
        if let Err(errors) = validator.validate(&decoded.value) {
            panic!(
                "canonical project schema errors: {:?}",
                errors.map(|error| error.to_string()).collect::<Vec<_>>()
            );
        };
    }
}

#[test]
fn local_type_resolution_preserves_field_addressed_diagnostics() {
    let source = std::str::from_utf8(PROJECT).unwrap().replace(
        "typeRef: postal-code, required: true",
        "typeRef: postal-code, required: 'true'",
    );
    let report =
        registry_breg::contract::read_project_yaml("registry.yaml", source.as_bytes()).unwrap_err();
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.path.ends_with("/required"))
        .expect("required field diagnostic");
    assert!(diagnostic
        .source
        .as_ref()
        .and_then(|source| source.line)
        .is_some());
}

fn ordered_effect(
    id: &str,
    dependencies: &[&str],
    operation: registry_breg::contract::Operation,
) -> registry_breg::model::CompiledPlanEffect {
    registry_breg::model::CompiledPlanEffect {
        id: id.into(),
        target: registry_breg::model::CompiledPlanTarget {
            entity_id: "record".into(),
            binding: registry_breg::model::CompiledPlanTargetBinding::Create,
        },
        operation,
        mutations: Vec::new(),
        depends_on: dependencies.iter().map(|id| (*id).into()).collect(),
    }
}
#[test]
fn ordered_plan_validator_preserves_authored_order() {
    use registry_breg::contract::Operation::Create;
    let effects = vec![
        ordered_effect("z", &[], Create),
        ordered_effect("a", &["z"], Create),
    ];
    let validated = registry_breg::plan::order_plan_effects(effects.clone()).unwrap();
    assert_eq!(validated, effects);
}
#[test]
fn ordered_plan_validator_refuses_forward_unknown_cycle_and_noncreate_refs() {
    use registry_breg::contract::Operation::{Create, Patch};
    let cases = vec![
        vec![
            ordered_effect("a", &["z"], Create),
            ordered_effect("z", &[], Create),
        ],
        vec![ordered_effect("a", &["missing"], Create)],
        vec![
            ordered_effect("a", &["z"], Create),
            ordered_effect("z", &["a"], Create),
        ],
        vec![
            ordered_effect("a", &[], Patch),
            ordered_effect("z", &["a"], Create),
        ],
        vec![
            ordered_effect("a", &[], Create),
            ordered_effect("a", &[], Create),
        ],
    ];
    for effects in cases {
        assert!(registry_breg::plan::order_plan_effects(effects).is_err());
    }
}

#[test]
fn authored_action_input_display_survives_source_and_compilation() {
    let mut project = parse_project_yaml(PROJECT).unwrap();
    let input = &mut project.actions[0].inputs[0];
    input.display.label = Some("Facility identifier".into());
    input.display.description = Some("The institution's stable facility code.".into());
    let model = compile(&project).unwrap();
    let input = &model
        .actions()
        .actions
        .iter()
        .find(|action| action.id == project.actions[0].id)
        .unwrap()
        .inputs[0];
    assert_eq!(input.display.label.as_deref(), Some("Facility identifier"));
    assert_eq!(
        input.display.description.as_deref(),
        Some("The institution's stable facility code.")
    );
}

#[test]
fn input_and_refusal_labels_are_presentation_not_frozen_meaning() {
    use serde_json::json;
    let mut value: serde_json::Value = project_source();
    value["actions"][1]["plan"]["refusals"] =
        json!([{ "code":"invalid-address", "label":"Old label" }]);
    let source =
        registry_breg::contract::parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let before = compile(&source).unwrap();
    value["actions"][0]["inputs"][0]["display"] =
        json!({"label":"A clearer label", "description":"Presentation only"});
    value["actions"][1]["plan"]["refusals"] =
        json!([{ "code":"invalid-address", "label":"Use a distinct address" }]);
    let project =
        registry_breg::contract::parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let after = compile(&project).unwrap();
    for action in &before.actions().actions {
        let successor = after
            .actions()
            .actions
            .iter()
            .find(|entry| entry.id == action.id)
            .unwrap();
        assert_eq!(action.definition_revision, successor.definition_revision);
    }
}

#[test]
fn named_review_authority_status_is_a_service_only_target_free_interface() {
    use serde_json::json;
    let source = parse_project_yaml(PROJECT).unwrap();
    let model = compile(&source).unwrap();
    let action = model
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        panic!("proposal")
    };
    let grant = proposal
        .permissions
        .iter()
        .find(|grant| grant.profile_id == "casework-review-status")
        .unwrap();
    assert_eq!(grant.review_authority.as_deref(), Some("casework"));
    assert!(grant.targets.is_empty());
    for (field, value) in [
        ("reviewAuthority", json!("other")),
        ("operations", json!(["get-review-context"])),
    ] {
        let mut value_source: serde_json::Value = project_source();
        let profile = value_source["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["id"] == "casework-review-status")
            .unwrap();
        profile["permissions"]["proposals"][0][field] = value;
        let project = registry_breg::contract::parse_project_json(
            &serde_json::to_vec(&value_source).unwrap(),
        )
        .unwrap();
        assert!(compile(&project).is_err());
    }
}

#[test]
fn omitted_proposal_application_uses_the_bounded_builtin_executor() {
    use serde_json::json;
    let mut value: serde_json::Value = project_source();
    value["actions"][2]["execution"]["proposal"]
        .as_object_mut()
        .unwrap()
        .remove("application");
    let source =
        registry_breg::contract::parse_project_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    let model = compile(&source).unwrap();
    for action in model
        .actions()
        .actions
        .iter()
        .filter(|action| action.id != "register-facility")
    {
        let CompiledActionExecution::Proposal { proposal } = &action.execution else {
            panic!("proposal")
        };
        assert!(matches!(
            proposal.application,
            registry_breg::model::CompiledProposalApplication::Automatic {
                maximum_attempts: 3
            }
        ));
        let grant = proposal.system_apply_grant.as_ref().unwrap();
        assert_eq!(grant.action_revision, action.definition_revision);
        assert!(!grant.targets.is_empty());
    }
    assert_eq!(
        json!(registry_breg::contract::ProposalApplicationSource::default()),
        json!({"mode":"automatic","maximumAttempts":3})
    );
}

#[test]
fn public_action_export_comes_from_the_compiled_owner_contract() {
    let model = compile(&parse_project_yaml(PROJECT).unwrap()).unwrap();
    let artifact = model
        .artifacts()
        .get("generated/action-contracts.json")
        .unwrap();
    let exported: serde_json::Value = serde_json::from_slice(&artifact.bytes).unwrap();
    assert_eq!(
        exported["apiVersion"],
        registry_breg::artifacts::ACTION_CONTRACTS_API_VERSION
    );
    assert_eq!(
        exported["kind"],
        registry_breg::artifacts::ACTION_CONTRACTS_KIND
    );
    let format_schema: serde_json::Value = serde_json::from_slice(
        &model
            .artifacts()
            .get("generated/action-contracts.schema.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&format_schema)
        .unwrap();
    assert!(validator.is_valid(&exported));
    let mut unversioned = exported.clone();
    unversioned.as_object_mut().unwrap().remove("apiVersion");
    assert!(!validator.is_valid(&unversioned));
    let mut unknown = exported.clone();
    unknown["actions"][0]["handler"] = serde_json::json!({"source":"private-code"});
    assert!(!validator.is_valid(&unknown));
    let openapi: serde_json::Value = serde_json::from_slice(
        &model
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let actions = exported["actions"].as_array().unwrap();
    assert_eq!(actions.len(), model.actions().actions.len());
    for action in &model.actions().actions {
        let entry = actions
            .iter()
            .find(|entry| entry["id"] == action.id)
            .unwrap();
        assert_eq!(entry["revision"], action.definition_revision);
        assert_eq!(
            entry["input"],
            openapi["components"]["schemas"][format!("action-{}-invoke-input", action.id)]
        );
        assert_eq!(
            entry["output"],
            openapi["components"]["schemas"][format!("action-{}-invoke-response", action.id)]
        );
        assert!(entry.get("systemApplyProfile").is_none());
        let keys = entry
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            keys.is_subset(
                &[
                    "id",
                    "revision",
                    "display",
                    "mode",
                    "input",
                    "output",
                    "review",
                    "application",
                    "declaredRefusal"
                ]
                .into_iter()
                .collect()
            )
        );
        assert!(!entry.to_string().contains("correct-address.rhai"));
    }
    let correction = actions
        .iter()
        .find(|entry| entry["id"] == "correct-address")
        .unwrap();
    assert_eq!(correction["mode"], "proposal");
    assert!(correction.get("review").is_some());
    assert!(correction.get("application").is_some());
    assert!(
        correction["declaredRefusal"]
            .to_string()
            .contains("invalid-postal-code")
    );
    let refusal = jsonschema::JSONSchema::compile(&correction["declaredRefusal"]).unwrap();
    assert!(refusal.is_valid(&serde_json::json!({"refusalCode":"invalid-postal-code"})));
    assert!(!refusal.is_valid(&serde_json::json!({"refusalCode":"transport-error"})));
    assert!(!refusal.is_valid(
        &serde_json::json!({"refusalCode":"invalid-postal-code","detail":"private-input"})
    ));
}

#[test]
fn coordinator_information_request_declares_and_executes_blank_reason_refusal() {
    use registry_breg::action_handler::{ActionHandlerOutcome, evaluate_action};
    let project = parse_project_yaml(include_bytes!(
        "../../../products/breg/examples/coordinator-actions/registry.yaml"
    ))
    .unwrap();
    let registry = compile_project_with_assets(&project, &[], &[ModuleAssetSource { module: None, path: "scripts/request-information.rhai".into(), bytes: include_bytes!("../../../products/breg/examples/coordinator-actions/scripts/request-information.rhai").to_vec() }], CompileProfile::Authoring).unwrap();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "request-information")
        .unwrap();
    let input =
        serde_json::json!({"application":"00000000-0000-4000-8000-000000000001","reason":"   "})
            .as_object()
            .unwrap()
            .clone();
    let outcome = evaluate_action(
        action,
        &input,
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    )
    .unwrap();
    let ActionHandlerOutcome::Refusal(refusal) = outcome else {
        panic!("whitespace reason is a declared business refusal")
    };
    assert_eq!(refusal.code, "invalid-reason");
    assert_eq!(refusal.field.as_deref(), Some("reason"));
}
