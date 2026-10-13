// SPDX-License-Identifier: Apache-2.0
use registry_breg::{
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_yaml, ModuleAssetSource, RegistryProject},
    model::{CompiledActionExecution, CompiledPlanValue, CompiledProposalReview},
};
const MINIMAL: &[u8] = include_bytes!("../../../products/breg/examples/refactor/minimal.yaml");
const PROJECT: &[u8] = include_bytes!("../../../products/breg/examples/refactor/project.yaml");
const FUNCTION: &[u8] =
    include_bytes!("../../../products/breg/examples/refactor/plans/correct-address.rhai");
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
    assert!(model.entities().values().all(|record_type| record_type.change_request.is_none()));
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
    assert!(model.entities().values().all(|record_type| record_type.change_request.is_none()));
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
fn explicit_dependencies_reject_unknown_edges_and_cycles() {
    let original = std::str::from_utf8(PROJECT).unwrap();
    for dependency in ["assignment", "missing"] {
        let source = original.replace(
            "- id: facility\n          target:",
            &format!("- id: facility\n          after: [{dependency}]\n          target:"),
        );
        let project = parse_project_yaml(source.as_bytes()).unwrap();
        let failure = compile(&project).expect_err("invalid dependency refuses compilation");
        assert!(failure.diagnostics().iter().any(|diagnostic| diagnostic
            .code
            .starts_with("breg.action.effect-dependency-")));
    }
}
#[test]
fn immediate_mode_cannot_bypass_target_proposal_policy() {
    let mut project = parse_project_yaml(PROJECT).unwrap();
    project.actions.iter_mut().find(|action|action.id=="deactivate-facility")
        .unwrap().execution = registry_breg::contract::ActionExecutionSource::Immediate;
    for profile in &mut project.access_profiles {
        profile.permissions.proposals.retain(|grant|grant.action!="deactivate-facility");
        for grant in &mut profile.permissions.actions {
            if grant.action=="deactivate-facility" {
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
        .replace("v2alpha1", "v1alpha1");
    assert!(parse_project_yaml(source.as_bytes()).is_err());
    let source = std::str::from_utf8(MINIMAL)
        .unwrap()
        .replace("recordTypes:", "entities:");
    assert!(parse_project_yaml(source.as_bytes()).is_err());
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
