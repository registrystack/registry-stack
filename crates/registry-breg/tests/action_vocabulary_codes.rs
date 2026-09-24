// SPDX-License-Identifier: Apache-2.0

//! An action input migrates without review only when every code it gained is
//! new to its vocabulary in the same revision. An input that starts accepting
//! a code its vocabulary already had changes what the action does, so it stays
//! a reviewed action change.

#![cfg(feature = "runtime")]

use registry_breg::compiler::{compile_project, module_digest, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::package::{
    change_set_to_applicable_migration_plan, compiled_registry_change_set,
    compiled_registry_change_set_from_baseline, CompiledRegistryChangeClass,
    CompiledRegistryChangeCode, CompiledRegistryChangeSet, CompiledRegistryMigrationBaseline,
};
use registry_breg::CompiledRegistry;

const CONSENT_PROJECT: &str =
    include_str!("../../../products/breg/fixtures/consent-person-registry/registry.yaml");
const CONSENT_MODULE: &str = include_str!(
    "../../../products/breg/fixtures/consent-person-registry/modules/consent-person/module.yaml"
);
const CONSENT_CORE_MODULE: &str = include_str!(
    "../../../products/breg/fixtures/consent-person-registry/modules/consent-person-registry-core/module.yaml"
);
const ASSET_PROJECT: &str =
    include_str!("../../../products/breg/fixtures/asset-registration-actions/registry.yaml");
const ASSET_MODULE: &str = include_str!(
    "../../../products/breg/fixtures/asset-registration-actions/modules/asset-registration-actions-core/module.yaml"
);

const WITHDRAW_DECISION: &str = "{id: decision, type: vocabulary-code, vocabulary: consent-decision, values: [withdrawn], required: true, classification: internal}";
const INSPECTION_RESULT_INPUT: &str = "{id: inspection-result, apiName: initialResult, type: vocabulary-code, vocabulary: inspection-result, required: true, classification: internal}";

/// Compile an edited fixture, relocking its modules as `bregctl project lock`
/// would after the edit.
fn compile(project: &str, modules: &[&str]) -> CompiledRegistry {
    let mut project = parse_project_yaml(project.as_bytes()).expect("fixture project parses");
    let modules = modules
        .iter()
        .map(|module| parse_module_yaml(module.as_bytes()).expect("fixture module parses"))
        .collect::<Vec<_>>();
    for lock in &mut project.modules {
        let module = modules
            .iter()
            .find(|module| module.id == lock.id)
            .expect("every locked module is supplied");
        lock.digest = Some(module_digest(module));
    }
    compile_project(&project, &modules, CompileProfile::Authoring).expect("fixture compiles")
}

fn consent(project: &str, module: &str) -> CompiledRegistry {
    compile(project, &[module, CONSENT_CORE_MODULE])
}

/// Replace exactly one occurrence, so a fixture edit cannot silently miss.
fn replace_once(source: &str, from: &str, to: &str) -> String {
    assert_eq!(source.matches(from).count(), 1, "{from}");
    source.replacen(from, to, 1)
}

fn action_change(
    changes: &CompiledRegistryChangeSet,
    action: &str,
) -> (CompiledRegistryChangeCode, CompiledRegistryChangeClass) {
    let found = changes
        .changes
        .iter()
        .filter(|change| change.target.member_id.as_deref() == Some(action))
        .map(|change| (change.code, change.class))
        .collect::<Vec<_>>();
    assert_eq!(found.len(), 1, "{action}: {:#?}", changes.changes);
    found[0]
}

#[test]
fn a_withdraw_action_that_starts_accepting_given_is_a_reviewed_action_change() {
    let before = consent(CONSENT_PROJECT, CONSENT_MODULE);
    let widened = replace_once(
        CONSENT_MODULE,
        WITHDRAW_DECISION,
        &WITHDRAW_DECISION.replace("[withdrawn]", "[withdrawn, given]"),
    );
    let after = consent(CONSENT_PROJECT, &widened);
    let changes = compiled_registry_change_set(&before, &after, "prior-package");

    assert_eq!(
        action_change(&changes, "withdraw-person-consent"),
        (
            CompiledRegistryChangeCode::ActionChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange
        )
    );
    assert!(
        change_set_to_applicable_migration_plan(&changes).is_err(),
        "a withdraw action that can now give consent needs review"
    );
}

#[test]
fn a_recipient_new_to_its_vocabulary_migrates_the_actions_that_pick_it_up() {
    let before = consent(CONSENT_PROJECT, CONSENT_MODULE);
    let project = replace_once(
        CONSENT_PROJECT,
        "  groups:\n",
        "    - id: school-meals\n      name: School Meals Programme\n      contact: privacy@school-meals.example.gov\n      clients: []\n  groups:\n",
    );
    let after = consent(&project, CONSENT_MODULE);
    let changes = compiled_registry_change_set(&before, &after, "prior-package");

    for action in [
        "give-person-consent",
        "refuse-person-consent",
        "withdraw-person-consent",
        "record-person-consent-assisted",
    ] {
        assert_eq!(
            action_change(&changes, action),
            (
                CompiledRegistryChangeCode::ActionVocabularyCodesAdded,
                CompiledRegistryChangeClass::CompatibleAdditive
            )
        );
    }
    assert!(change_set_to_applicable_migration_plan(&changes).is_ok());
}

#[test]
fn a_purpose_new_to_its_vocabulary_migrates_the_actions_that_pick_it_up() {
    let before = consent(CONSENT_PROJECT, CONSENT_MODULE);
    let project = replace_once(
        CONSENT_PROJECT,
        "values: [food-assistance, health-referral]",
        "values: [food-assistance, health-referral, school-meals]",
    );
    let after = consent(&project, CONSENT_MODULE);
    let changes = compiled_registry_change_set(&before, &after, "prior-package");

    assert_eq!(
        action_change(&changes, "give-person-consent"),
        (
            CompiledRegistryChangeCode::ActionVocabularyCodesAdded,
            CompiledRegistryChangeClass::CompatibleAdditive
        )
    );
    assert!(change_set_to_applicable_migration_plan(&changes).is_ok());
}

/// A new code alone is additive, but an input that also picks up a code its
/// vocabulary already had is not, even in the same revision.
#[test]
fn a_new_code_does_not_carry_an_existing_code_through_review() {
    let before = consent(CONSENT_PROJECT, CONSENT_MODULE);
    let project = replace_once(
        CONSENT_PROJECT,
        "values: [given, refused, withdrawn, invalidated]",
        "values: [given, refused, withdrawn, invalidated, lapsed]",
    );
    let widened = replace_once(
        CONSENT_MODULE,
        WITHDRAW_DECISION,
        &WITHDRAW_DECISION.replace("[withdrawn]", "[withdrawn, lapsed, given]"),
    );
    let after = consent(&project, &widened);
    let changes = compiled_registry_change_set(&before, &after, "prior-package");
    assert_eq!(
        action_change(&changes, "withdraw-person-consent"),
        (
            CompiledRegistryChangeCode::ActionChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange
        )
    );
    assert!(change_set_to_applicable_migration_plan(&changes).is_err());

    let only_new = replace_once(
        CONSENT_MODULE,
        WITHDRAW_DECISION,
        &WITHDRAW_DECISION.replace("[withdrawn]", "[withdrawn, lapsed]"),
    );
    let after = consent(&project, &only_new);
    let changes = compiled_registry_change_set(&before, &after, "prior-package");
    assert_eq!(
        action_change(&changes, "withdraw-person-consent"),
        (
            CompiledRegistryChangeCode::ActionVocabularyCodesAdded,
            CompiledRegistryChangeClass::CompatibleAdditive
        )
    );
}

#[test]
fn an_action_status_widened_to_an_existing_code_is_a_reviewed_action_change() {
    let narrow = replace_once(
        ASSET_MODULE,
        INSPECTION_RESULT_INPUT,
        &INSPECTION_RESULT_INPUT.replace("required: true", "values: [passed], required: true"),
    );
    let wide = replace_once(
        ASSET_MODULE,
        INSPECTION_RESULT_INPUT,
        &INSPECTION_RESULT_INPUT
            .replace("required: true", "values: [passed, failed], required: true"),
    );
    let before = compile(ASSET_PROJECT, &[&narrow]);
    let after = compile(ASSET_PROJECT, &[&wide]);
    let changes = compiled_registry_change_set(&before, &after, "prior-package");

    assert_eq!(
        action_change(&changes, "register-asset-with-inspection"),
        (
            CompiledRegistryChangeCode::ActionChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange
        )
    );
    assert!(change_set_to_applicable_migration_plan(&changes).is_err());
}

/// A retained baseline written before input vocabularies were recorded cannot
/// tell a new code from an existing one, so it fails closed to review.
#[test]
fn a_baseline_without_input_vocabularies_keeps_every_widening_under_review() {
    let before = consent(CONSENT_PROJECT, CONSENT_MODULE);
    let project = replace_once(
        CONSENT_PROJECT,
        "values: [food-assistance, health-referral]",
        "values: [food-assistance, health-referral, school-meals]",
    );
    let after = consent(&project, CONSENT_MODULE);
    let mut baseline = serde_json::to_value(CompiledRegistryMigrationBaseline::from_compiled(
        "prior-package",
        &before,
    ))
    .unwrap();
    assert!(
        baseline["actions"]
            .as_object_mut()
            .unwrap()
            .remove("inputVocabularies")
            .is_some(),
        "the baseline records the vocabularies its action inputs use"
    );
    let baseline: CompiledRegistryMigrationBaseline = serde_json::from_value(baseline).unwrap();
    let changes = compiled_registry_change_set_from_baseline(&baseline, &after, "prior-package");

    assert_eq!(
        action_change(&changes, "give-person-consent"),
        (
            CompiledRegistryChangeCode::ActionChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange
        )
    );
    assert!(change_set_to_applicable_migration_plan(&changes).is_err());
}
