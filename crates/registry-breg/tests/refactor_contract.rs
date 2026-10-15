// SPDX-License-Identifier: Apache-2.0
use registry_breg::{
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_yaml, ModuleAssetSource, RegistryProject},
    model::{CompiledActionExecution, CompiledPlanValue, CompiledProposalReview},
};
const MINIMAL: &[u8] = include_bytes!("../../../products/breg/examples/minimal/registry.yaml");
const PROJECT: &[u8] = include_bytes!("../../../products/breg/examples/facility/registry.yaml");
const FUNCTION: &[u8] =
    include_bytes!("../../../products/breg/examples/facility/plans/correct-address.rhai");
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
    value["actions"][action_index]["execution"]["proposal"]["reviewContext"]["fields"]
        ["supportingDocument"]["slot"] = json!("supporting-file");
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
fn proposal_attachment_download_schema_requires_a_positive_u32_submission_version() {
    use serde_json::json;
    let model = compile(&parse_project_yaml(PROJECT).unwrap()).unwrap();
    let openapi: serde_json::Value = serde_json::from_slice(
        &model
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let attachment =
        &openapi["paths"]["/v1/proposals/{proposal_id}/attachments/supporting-document"];
    let parameter = attachment["get"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|parameter| parameter["name"] == "submissionVersion")
        .expect("attachment downloads bind an exact submitted version");
    assert_eq!(parameter["in"], "query");
    assert_eq!(parameter["required"], true);
    let validator = jsonschema::JSONSchema::compile(&parameter["schema"]).unwrap();
    for version in [json!(1), json!(u32::MAX)] {
        assert!(validator.is_valid(&version), "{version}");
    }
    for version in [
        json!(-1),
        json!(0),
        json!(u64::from(u32::MAX) + 1),
        json!(1.5),
        json!("1"),
    ] {
        assert!(!validator.is_valid(&version), "{version}");
    }

    // An unsubmitted draft remains version zero, with unversioned slot edits.
    let proposal_version_schema = &openapi["paths"]["/v1/proposals/{proposal_id}"]["get"]
        ["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
        ["submissionVersion"];
    assert!(jsonschema::JSONSchema::compile(proposal_version_schema)
        .unwrap()
        .is_valid(&json!(0)));
    for method in ["patch", "delete"] {
        assert!(!attachment[method]["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|parameter| parameter["name"] == "submissionVersion"));
    }
}

#[test]
fn proposal_commands_declare_the_rejected_conflict_and_documents_require_turn() {
    let model = compile(&parse_project_yaml(PROJECT).unwrap()).unwrap();
    let openapi: serde_json::Value = serde_json::from_slice(
        &model
            .artifacts()
            .get("generated/openapi.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    let mut commands = 0;
    for (path, item) in openapi["paths"].as_object().unwrap() {
        let Some(operation) = item.get("post") else {
            continue;
        };
        let Some(command) = operation["operationId"]
            .as_str()
            .and_then(|id| id.strip_prefix("proposals."))
        else {
            continue;
        };
        if command == "start" {
            continue;
        }
        commands += 1;
        assert!(
            operation["responses"]["409"]["description"].is_string(),
            "{path} {command} declares 409"
        );
        let required = operation["responses"]["200"]["content"]["application/json"]["schema"]
            ["required"]
            .as_array()
            .unwrap();
        assert!(
            required.iter().any(|name| name == "turn"),
            "{path} {command} requires turn"
        );
    }
    assert!(
        commands >= 7,
        "every Proposal command is checked: {commands}"
    );
    let list = &openapi["paths"]["/v1/proposals"]["get"];
    let limit = list["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|parameter| parameter["name"] == "limit")
        .unwrap();
    assert!(limit["description"]
        .as_str()
        .is_some_and(|text| text.contains("keep paging while `nextCursor` is present")));
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
        schema.schema["properties"]["changes"]["items"]["properties"]["after"]["properties"]
            ["city"]["maxLength"],
        json!(120)
    );
    assert!(schema.revision.starts_with("sha256:"));
    let action_index = value["actions"]
        .as_array()
        .unwrap()
        .iter()
        .position(|action| action["id"] == "correct-address")
        .unwrap();
    value["actions"][action_index]["execution"]["proposal"]["review"]["policy"]["version"] =
        json!("1");
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
fn review_context_document_schema_binds_slot_meaning_and_closed_retained_values() {
    use registry_breg::{compiler::review_context::compile_schema, contract::parse_project_json};
    use serde_json::{json, Value};
    let mut source = project_source();
    let index = source["actions"]
        .as_array()
        .unwrap()
        .iter()
        .position(|action| action["id"] == "correct-address")
        .unwrap();
    source["actions"][index]["execution"]["proposal"]["reviewContext"]["fields"]["document"] =
        json!({"type":"document","slot":"supporting-document"});
    let schema_for = |source: &Value| {
        let registry =
            compile(&parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap()).unwrap();
        compile_schema(
            &registry,
            registry
                .actions()
                .actions
                .iter()
                .find(|action| action.id == "correct-address")
                .unwrap(),
        )
        .unwrap()
        .unwrap()
    };
    let baseline = schema_for(&source);
    let schema = &baseline.schema["properties"]["document"];
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(schema)
        .unwrap();
    assert!(
        validator.is_valid(&Value::Null),
        "absent optional frozen slot"
    );
    let value = json!({"type":"document","slotId":"supporting-document","sha256":"a".repeat(64),
        "contentType":"text/plain","byteSize":2_000_000,
        "download":{"method":"GET","operation":"get-review-context","accessProfile":"reviewer_one",
            "path":format!("/v1/proposals/00000000-0000-4000-8000-000000000001/attachments/supporting-document?submissionVersion=1&reviewContextField=document&effectDigest=sha256%3A{}&contextSchemaDigest=sha256%3A{}", "b".repeat(64), "c".repeat(64))}});
    assert!(
        validator.is_valid(&value),
        "retained content need not match today's upload policy"
    );
    for (pointer, invalid) in [
        ("/slotId", json!("other")),
        ("/sha256", json!("A".repeat(64))),
        ("/byteSize", json!(0)),
        ("/byteSize", json!(16 * 1024 * 1024 + 1)),
        ("/contentType", json!("text/plain; charset=utf-8")),
        ("/download/operation", json!("get")),
        ("/download/path", json!("https://other.example/file")),
    ] {
        let mut invalid_value = value.clone();
        *invalid_value.pointer_mut(pointer).unwrap() = invalid;
        assert!(
            !validator.is_valid(&invalid_value),
            "{pointer}: {invalid_value}"
        );
    }
    for pointer in ["", "/download"] {
        let mut invalid = value.clone();
        invalid
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), json!(true));
        assert!(!validator.is_valid(&invalid));
    }
    for (key, changed) in [
        ("classification", json!("internal")),
        ("maximumBytes", json!(512)),
        ("contentTypes", json!(["text/plain"])),
        ("required", json!(true)),
    ] {
        let mut changed_source = source.clone();
        changed_source["actions"][index]["execution"]["proposal"]["attachments"][0][key] = changed;
        let changed = schema_for(&changed_source);
        assert_ne!(baseline.revision, changed.revision, "{key}");
        assert_ne!(baseline.digest, changed.digest, "{key}");
    }
    let mut remapped = source.clone();
    let mut second = remapped["actions"][index]["execution"]["proposal"]["attachments"][0].clone();
    second["id"] = json!("alternate");
    remapped["actions"][index]["execution"]["proposal"]["attachments"]
        .as_array_mut()
        .unwrap()
        .push(second);
    remapped["actions"][index]["execution"]["proposal"]["reviewContext"]["fields"]["document"]
        ["slot"] = json!("alternate");
    assert_ne!(baseline.digest, schema_for(&remapped).digest);
    let mut pinned = source.clone();
    pinned["actions"][index]["execution"]["proposal"]["review"]["policy"]["version"] = json!("1");
    pinned["actions"][index]["execution"]["proposal"]["review"]["policy"]["digest"] =
        json!(format!("sha256:{}", "d".repeat(64)));
    assert_eq!(baseline.bytes, schema_for(&pinned).bytes);
    source["actions"][index]["execution"]["proposal"]["reviewContext"]["fields"]["document"]
        ["slot"] = json!("unknown");
    assert!(
        compile(&parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap())
            .unwrap_err()
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "breg.proposal.context-mapping-invalid")
    );
    source["actions"][index]["execution"]["proposal"]["reviewContext"]["fields"]["document"]
        ["extra"] = json!(true);
    assert!(parse_project_json(&serde_json::to_vec(&source).unwrap()).is_err());
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
    if let Err(errors) = validator.validate(&exported) {
        panic!(
            "action export does not satisfy its schema: {:?}",
            errors.map(|error| error.to_string()).collect::<Vec<_>>()
        );
    }
    let reviewed_index = exported["actions"]
        .as_array()
        .unwrap()
        .iter()
        .position(|action| action["review"]["type"] == "required")
        .unwrap();
    for selection in [
        serde_json::json!({"id":"policy"}),
        serde_json::json!({"id":"policy","version":"1","digest":format!("sha256:{}", "a".repeat(64))}),
        serde_json::json!({"id":"policy","version":"1"}),
        serde_json::json!({"id":"policy","digest":format!("sha256:{}", "a".repeat(64))}),
        serde_json::json!({"id":"policy","version":null,"digest":null}),
    ] {
        let protocol_accepts =
            serde_json::from_value::<registry_review_protocol::PolicySelection>(selection.clone())
                .is_ok_and(|selection| selection.check().is_ok());
        let mut variant = exported.clone();
        variant["actions"][reviewed_index]["review"]["policy"] = selection.clone();
        assert_eq!(
            validator.is_valid(&variant),
            protocol_accepts,
            "selection schema differs from shared protocol: {selection}"
        );
    }
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
        assert!(keys.is_subset(
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
        ));
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
        correction.get("declaredRefusal").is_none(),
        "draft creation does not evaluate the Proposal plan"
    );
}

#[test]
fn review_policy_omits_both_pins_or_requires_one_complete_exact_binding() {
    use registry_breg::contract::parse_project_json;
    use registry_review_protocol::{ContentDigest, PolicyBinding};
    use serde_json::json;
    let mut source = project_source();
    let action = source["actions"]
        .as_array()
        .unwrap()
        .iter()
        .position(|action| action["id"] == "correct-address")
        .unwrap();
    let exact = PolicyBinding {
        id: "facility-address-review".into(),
        version: "1".into(),
        digest: ContentDigest::for_bytes(b"independently accepted policy"),
    };
    for selection in [json!({"id": exact.id}), json!(exact)] {
        source["actions"][action]["execution"]["proposal"]["review"]["policy"] = selection.clone();
        let registry =
            compile(&parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap()).unwrap();
        let action = registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == "correct-address")
            .unwrap();
        let CompiledActionExecution::Proposal { proposal } = &action.execution else {
            panic!("Proposal")
        };
        let CompiledProposalReview::Required { policy, .. } = &proposal.review else {
            panic!("Review")
        };
        assert!(policy.matches(&exact));
        assert_eq!(serde_json::to_value(policy).unwrap(), selection);
        assert!(!policy.matches(&PolicyBinding {
            id: "another-policy".into(),
            ..exact.clone()
        }));
    }
    for invalid in [
        json!({"id": exact.id, "version": exact.version}),
        json!({"id": exact.id, "digest": exact.digest}),
        json!({"id": exact.id, "version": null, "digest": null}),
    ] {
        source["actions"][action]["execution"]["proposal"]["review"]["policy"] = invalid;
        let result = parse_project_json(&serde_json::to_vec(&source).unwrap());
        assert!(result.is_err() || compile(&result.unwrap()).is_err());
    }
}

#[test]
fn proposal_start_route_uses_the_same_operation_id_as_metadata_and_openapi() {
    let model = compile(&parse_project_yaml(PROJECT).unwrap()).unwrap();
    let routes = &model.actions().routes;
    assert!(routes
        .iter()
        .any(|route| route.id == "actions.correct-address.start"));
    assert!(routes
        .iter()
        .any(|route| route.id == "actions.register-facility.invoke"));
    assert!(!routes
        .iter()
        .any(|route| route.id == "actions.correct-address.invoke"));
}

#[test]
fn review_context_meaning_binds_resolved_record_type_and_source_without_global_pin() {
    use registry_breg::compiler::review_context::{compile_schema, compile_schema_from_parts};
    use registry_breg::contract::FieldTypeSource;
    let registry = compile(&parse_project_yaml(PROJECT).unwrap()).unwrap();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    let original = compile_schema(&registry, action).unwrap().unwrap();
    let mut records = registry.entities().clone();
    let mut alternative = records["facility"].clone();
    alternative.id = "other-facility".into();
    records.insert(alternative.id.clone(), alternative);
    // Adding an unrelated Record type does not change the interface.
    assert_eq!(
        compile_schema_from_parts(registry.registry_id(), &records, action)
            .unwrap()
            .unwrap()
            .revision,
        original.revision
    );
    let mut rebound = action.clone();
    let input = rebound
        .inputs
        .iter_mut()
        .find(|input| input.id == "facility")
        .unwrap();
    let FieldTypeSource::Reference { target, .. } = &mut input.field_type else {
        panic!("reference input")
    };
    *target = "other-facility".into();
    let changed = compile_schema_from_parts(registry.registry_id(), &records, &rebound)
        .unwrap()
        .unwrap();
    assert_eq!(
        changed.schema["properties"], original.schema["properties"],
        "same JSON shape can describe a different Record source"
    );
    assert_ne!(changed.revision, original.revision);
    let mut new_source = action.clone();
    let registry_breg::model::CompiledActionExecution::Proposal { proposal } =
        &mut new_source.execution
    else {
        panic!("proposal")
    };
    let registry_breg::model::CompiledProposalReview::Required { source, .. } =
        &mut proposal.review
    else {
        panic!("review")
    };
    *source = "other-source".into();
    let changed = compile_schema_from_parts(registry.registry_id(), &records, &new_source)
        .unwrap()
        .unwrap();
    assert_ne!(changed.revision, original.revision);
    assert_eq!(
        changed.schema["x-registry-review-context"]["sourceNamespace"],
        "other-source"
    );
}

#[test]
fn frozen_change_projection_requires_explicit_unique_existing_fields() {
    for fields in [
        serde_json::json!([]),
        serde_json::json!(["missing"]),
        serde_json::json!(["city", "city"]),
    ] {
        let mut source = project_source();
        let action = source["actions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|action| action["id"] == "correct-address")
            .unwrap();
        action["execution"]["proposal"]["reviewContext"]["fields"]["changes"]["fields"] = fields;
        let project =
            registry_breg::contract::parse_project_json(&serde_json::to_vec(&source).unwrap())
                .unwrap();
        assert!(compile(&project).is_err());
    }
    let mut source = project_source();
    let action = source["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["id"] == "correct-address")
        .unwrap();
    action["execution"]["proposal"]["reviewContext"]["fields"]["changes"]["input"] =
        serde_json::json!("city");
    assert!(
        registry_breg::contract::parse_project_json(&serde_json::to_vec(&source).unwrap()).is_err(),
        "one context field has one source"
    );
}

#[test]
fn retired_authoring_keys_point_to_governed_replacements() {
    use registry_breg::contract::{read_module_yaml, read_project_yaml};
    use serde_json::json;

    let retired = json!({
        "changeControl": {"requiredFor": ["patch"]},
        "changeRequest": {},
        "accessProfiles": [{"requestVisibility": "owner", "readableRequestFields": ["reason"]}]
    });
    let actions = json!([{
        "commitGuards": {"targets": [{"equalsInput": "reason"}]},
        "plan": {"type": "fixed", "effects": [{"set": {"reason": {"fromField": "reason"}}}]}
    }]);
    let mut project = project_source();
    project["recordTypes"][0] = retired.clone();
    project["actions"] = actions.clone();
    let report =
        read_project_yaml("registry.json", &serde_json::to_vec(&project).unwrap()).unwrap_err();
    for (path, replacement) in [
        ("/recordTypes/0/changeControl", "mutationPolicy"),
        ("/recordTypes/0/changeRequest", "execution.proposal"),
        (
            "/recordTypes/0/accessProfiles/0/requestVisibility",
            "ownership: caller",
        ),
        (
            "/recordTypes/0/accessProfiles/0/readableRequestFields",
            "readableInputs",
        ),
        (
            "/actions/0/commitGuards/targets/0/equalsInput",
            "equalsFromInput",
        ),
        (
            "/actions/0/plan/effects/0/set/reason/fromField",
            "fromInput",
        ),
    ] {
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|d| d.path == path)
            .unwrap();
        assert_eq!(diagnostic.code, "config.removed-key");
        assert!(
            diagnostic.suggested_action.contains(replacement),
            "{}",
            report.render_human()
        );
    }
    let module = json!({"apiVersion": "id.registrystack.org/formats/breg/module/v1alpha1",
        "kind": "BRegModule", "recordTypes": [retired.clone()], "extendRecordTypes": [retired], "actions": actions});
    let report =
        read_module_yaml("module.json", &serde_json::to_vec(&module).unwrap()).unwrap_err();
    assert!(
        report
            .diagnostics()
            .iter()
            .all(|d| d.code == "config.removed-key"),
        "{}",
        report.render_human()
    );
    assert!(report
        .diagnostics()
        .iter()
        .any(|d| d.path == "/extendRecordTypes/0/changeControl"
            && d.suggested_action.contains("mutationPolicy")));
}

#[test]
fn retired_request_hook_points_to_proposal_observers() {
    use registry_breg::contract::read_project_yaml;
    use serde_json::json;
    let mut project = project_source();
    project["recordTypes"][0]["hooks"] = json!([{
        "id": "observe-lifecycle", "phase": "after", "trigger": "request-lifecycle", "projection": []
    }]);
    let report =
        read_project_yaml("registry.json", &serde_json::to_vec(&project).unwrap()).unwrap_err();
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|d| d.path == "/recordTypes/0/hooks/0/trigger")
        .unwrap();
    assert!(
        diagnostic
            .suggested_action
            .contains("execution.proposal.hooks"),
        "{}",
        report.render_human()
    );
    assert!(diagnostic.suggested_action.contains("transitions"));
    // The same authored hook still accepts its committed Record trigger.
    project["recordTypes"][0]["hooks"][0]["trigger"] = json!("created");
    read_project_yaml("registry.json", &serde_json::to_vec(&project).unwrap()).unwrap();
}
