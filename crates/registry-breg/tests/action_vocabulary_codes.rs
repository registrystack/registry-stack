// SPDX-License-Identifier: Apache-2.0

//! Frozen native Action revisions require review when their accepted
//! vocabulary, inputs, conditions, or effects change. Record field widening
//! remains independently additive, and an unrelated optional target field does
//! not turn every Action over that Record type into a reviewed change.

#![cfg(feature = "runtime")]

use registry_breg::compiler::{compile_project, module_digest, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::package::{
    change_set_to_applicable_migration_plan, compiled_registry_change_set,
    CompiledRegistryChangeClass, CompiledRegistryChangeCode, CompiledRegistryChangeSet,
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
const ASSET_PROJECT: &str = include_str!(
    "../../../products/breg/fixtures/asset-registration-actions-compact/registry.yaml"
);
const ASSET_MODULE: &str = include_str!(
    "../../../products/breg/fixtures/asset-registration-actions-compact/modules/asset-registration-actions-core/module.yaml"
);

const WITHDRAW_DECISION: &str = "{id: decision, type: vocabulary-code, vocabulary: consent-decision, values: [withdrawn], required: true, classification: internal}";
const INSPECTION_RESULT_INPUT: &str = "{id: inspection-result, apiName: initialResult, type: vocabulary-code, vocabulary: inspection-result, required: true, classification: internal}";
const IMPORT_SOURCE_REFERENCE: &str = "{id: source-reference, type: string, maximumLength: 255, required: true, classification: internal}";

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
    assert!(!changes
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::FieldVocabularyCodesAdded));
    assert!(
        change_set_to_applicable_migration_plan(&changes).is_err(),
        "a withdraw action that can now give consent needs review"
    );
}

#[test]
fn a_new_recipient_requires_review_for_the_actions_that_pick_it_up() {
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
                CompiledRegistryChangeCode::ActionChanged,
                CompiledRegistryChangeClass::AccessOrDisclosureChange
            )
        );
    }
    assert!(changes.changes.iter().any(|change| change.code
        == CompiledRegistryChangeCode::FieldVocabularyCodesAdded
        && change.class == CompiledRegistryChangeClass::CompatibleAdditive));
    assert!(change_set_to_applicable_migration_plan(&changes).is_err());
}

#[test]
fn a_new_purpose_requires_review_for_the_actions_that_pick_it_up() {
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
            CompiledRegistryChangeCode::ActionChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange
        )
    );
    assert!(changes.changes.iter().any(|change| change.code
        == CompiledRegistryChangeCode::FieldVocabularyCodesAdded
        && change.class == CompiledRegistryChangeClass::CompatibleAdditive));
    assert!(change_set_to_applicable_migration_plan(&changes).is_err());
}

/// New Record vocabulary codes are additive. Both existing and new accepted
/// input codes change the frozen Action and require review.
#[test]
fn new_and_existing_input_codes_both_require_action_review() {
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
            CompiledRegistryChangeCode::ActionChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange
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

#[test]
fn an_unrelated_vocabulary_leaves_every_action_semantically_unchanged() {
    let before = consent(CONSENT_PROJECT, CONSENT_MODULE);
    let project = replace_once(
        CONSENT_PROJECT,
        "vocabularies:\n",
        "vocabularies:\n  - id: unrelated-status\n    values: [active, inactive]\n",
    );
    let after = consent(&project, CONSENT_MODULE);
    let changes = compiled_registry_change_set(&before, &after, "prior-package");
    assert!(
        changes.changes.iter().all(|change| !matches!(
            change.code,
            CompiledRegistryChangeCode::ActionAdded
                | CompiledRegistryChangeCode::ActionChanged
                | CompiledRegistryChangeCode::ActionRemoved
        )),
        "{:#?}",
        changes.changes
    );
}

#[test]
fn an_unrelated_target_text_limit_is_additive_while_a_related_action_input_needs_review() {
    const SOURCE_REFERENCE: &str =
        "{id: source-reference, type: string, maximumLength: 255, classification: internal}";
    let with_limit = |max_length: u32| {
        replace_once(
            CONSENT_MODULE,
            SOURCE_REFERENCE,
            &format!(
                "{SOURCE_REFERENCE}\n  - {{id: review-note, type: text, maximumLength: {max_length}, classification: internal}}"
            ),
        )
    };
    let before = consent(CONSENT_PROJECT, &with_limit(255));

    let widened = compiled_registry_change_set(
        &before,
        &consent(CONSENT_PROJECT, &with_limit(1000)),
        "prior-package",
    );
    let changes = widened
        .changes
        .iter()
        .map(|change| (change.code, change.target.member_id.as_deref()))
        .collect::<Vec<_>>();
    assert_eq!(
        changes[0],
        (
            CompiledRegistryChangeCode::FieldLengthWidened,
            Some("review-note")
        )
    );
    assert!(widened.changes.iter().any(|change| change.code
        == CompiledRegistryChangeCode::FieldLengthWidened
        && change.class == CompiledRegistryChangeClass::CompatibleAdditive));
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert!(changes.iter().all(|(code, _)| !matches!(
        code,
        CompiledRegistryChangeCode::ActionAdded
            | CompiledRegistryChangeCode::ActionChanged
            | CompiledRegistryChangeCode::ActionRemoved
    )));
    change_set_to_applicable_migration_plan(&widened)
        .expect("an unrelated optional target field remains additive");

    let related = replace_once(
        CONSENT_MODULE,
        SOURCE_REFERENCE,
        &SOURCE_REFERENCE.replace("maximumLength: 255", "maximumLength: 1000"),
    );
    let related = replace_once(
        &related,
        IMPORT_SOURCE_REFERENCE,
        &IMPORT_SOURCE_REFERENCE.replace("maximumLength: 255", "maximumLength: 1000"),
    );
    let related = compiled_registry_change_set(
        &consent(CONSENT_PROJECT, CONSENT_MODULE),
        &consent(CONSENT_PROJECT, &related),
        "prior-package",
    );
    assert_eq!(
        action_change(&related, "import-person-consent"),
        (
            CompiledRegistryChangeCode::ActionChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange
        )
    );
    assert_eq!(related.changes.len(), 2, "{:#?}", related.changes);
    assert!(change_set_to_applicable_migration_plan(&related).is_err());
}

#[test]
fn an_unrelated_target_string_minimum_is_additive_while_a_related_input_needs_review() {
    const SOURCE_REFERENCE: &str =
        "{id: source-reference, type: string, maximumLength: 255, classification: internal}";
    let with_minimum = |min_length: u32| {
        replace_once(
            CONSENT_MODULE,
            SOURCE_REFERENCE,
            &format!(
                "{SOURCE_REFERENCE}\n  - {{id: review-code, type: string, minimumLength: {min_length}, maximumLength: 64, classification: internal}}"
            ),
        )
    };
    let before = consent(CONSENT_PROJECT, &with_minimum(8));

    let lowered = compiled_registry_change_set(
        &before,
        &consent(CONSENT_PROJECT, &with_minimum(2)),
        "prior-package",
    );
    let changes = lowered
        .changes
        .iter()
        .map(|change| (change.code, change.target.member_id.as_deref()))
        .collect::<Vec<_>>();
    assert_eq!(
        changes[0],
        (
            CompiledRegistryChangeCode::FieldLengthWidened,
            Some("review-code")
        )
    );
    assert!(lowered.changes.iter().any(|change| change.code
        == CompiledRegistryChangeCode::FieldLengthWidened
        && change.class == CompiledRegistryChangeClass::CompatibleAdditive));
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert!(changes.iter().all(|(code, _)| !matches!(
        code,
        CompiledRegistryChangeCode::ActionAdded
            | CompiledRegistryChangeCode::ActionChanged
            | CompiledRegistryChangeCode::ActionRemoved
    )));
    change_set_to_applicable_migration_plan(&lowered)
        .expect("an unrelated optional target field remains additive");

    let related_before = replace_once(
        CONSENT_MODULE,
        SOURCE_REFERENCE,
        &SOURCE_REFERENCE.replace("maximumLength: 255", "minimumLength: 8, maximumLength: 255"),
    );
    let related_before = replace_once(
        &related_before,
        IMPORT_SOURCE_REFERENCE,
        &IMPORT_SOURCE_REFERENCE
            .replace("maximumLength: 255", "minimumLength: 8, maximumLength: 255"),
    );
    let related_after = related_before.replace("minimumLength: 8", "minimumLength: 2");
    assert_eq!(
        related_before.matches("minimumLength: 8").count(),
        2,
        "both the Record field and Action input carry the reviewed constraint"
    );
    assert_eq!(related_after.matches("minimumLength: 2").count(), 2);
    let related = compiled_registry_change_set(
        &consent(CONSENT_PROJECT, &related_before),
        &consent(CONSENT_PROJECT, &related_after),
        "prior-package",
    );
    assert_eq!(
        action_change(&related, "import-person-consent"),
        (
            CompiledRegistryChangeCode::ActionChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange
        )
    );
    assert_eq!(related.changes.len(), 2, "{:#?}", related.changes);
    assert!(change_set_to_applicable_migration_plan(&related).is_err());
}

#[test]
fn a_narrowed_target_field_limit_stays_under_migration_review() {
    const SOURCE_REFERENCE: &str =
        "{id: source-reference, type: string, maximumLength: 255, classification: internal}";
    fn record_changes(
        changes: &CompiledRegistryChangeSet,
    ) -> Vec<(
        CompiledRegistryChangeCode,
        CompiledRegistryChangeClass,
        Option<&str>,
    )> {
        changes
            .changes
            .iter()
            .map(|change| {
                (
                    change.code,
                    change.class,
                    change.target.member_id.as_deref(),
                )
            })
            .collect()
    }
    let with_field = |field: &str| {
        replace_once(
            CONSENT_MODULE,
            SOURCE_REFERENCE,
            &format!("{SOURCE_REFERENCE}\n  - {field}"),
        )
    };

    for (before, after, field) in [
        (
            "{id: review-note, type: text, maximumLength: 255, classification: internal}",
            "{id: review-note, type: text, maximumLength: 100, classification: internal}",
            "review-note",
        ),
        (
            "{id: review-code, type: string, minimumLength: 8, maximumLength: 64, classification: internal}",
            "{id: review-code, type: string, minimumLength: 16, maximumLength: 64, classification: internal}",
            "review-code",
        ),
    ] {
        let narrowed = compiled_registry_change_set(
            &consent(CONSENT_PROJECT, &with_field(before)),
            &consent(CONSENT_PROJECT, &with_field(after)),
            "prior-package",
        );
        assert_eq!(
            record_changes(&narrowed),
            vec![(
                CompiledRegistryChangeCode::FieldTypeChanged,
                CompiledRegistryChangeClass::DestructiveOrIrreversible,
                Some(field)
            )],
            "{field}: a narrowed limit may reject stored values: {:#?}",
            narrowed.changes
        );
        assert!(
            change_set_to_applicable_migration_plan(&narrowed).is_err(),
            "{field}: a narrowed target field stays under migration review"
        );
    }
}
