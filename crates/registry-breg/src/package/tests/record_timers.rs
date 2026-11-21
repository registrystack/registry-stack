// SPDX-License-Identifier: Apache-2.0

use super::*;
#[cfg(feature = "tooling")]
use crate::tooling::{classify_registry_diff, DiffClassification};
use crate::{compile_project, parse_project_json, CompileProfile};
use serde_json::{json, Value};

const PRIOR_PACKAGE: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

#[test]
fn timer_policy_add_change_and_removal_are_explicit_reviewed_changes() {
    let without_timer = compile(&source(None, true));
    let primary = compile(&source(Some("activates-at"), true));
    let alternate = compile(&source(Some("alternate-activates-at"), true));

    let added = compiled_registry_change_set(&without_timer, &primary, PRIOR_PACKAGE);
    assert_timer_change(&added, CompiledRegistryChangeCode::TimerAdded);
    #[cfg(feature = "tooling")]
    {
        let classified = classify_registry_diff(&without_timer, &primary, PRIOR_PACKAGE);
        assert!(classified.changes.iter().any(|change| {
            change.change.code == CompiledRegistryChangeCode::TimerAdded
                && change.classification == DiffClassification::AccessChange
        }));
    }
    assert!(added
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::ActionAdded));

    let changed = compiled_registry_change_set(&primary, &alternate, PRIOR_PACKAGE);
    assert_timer_change(&changed, CompiledRegistryChangeCode::TimerChanged);
    assert_eq!(changed.changes.len(), 1, "{:#?}", changed.changes);

    let removed = compiled_registry_change_set(&primary, &without_timer, PRIOR_PACKAGE);
    assert_timer_change(&removed, CompiledRegistryChangeCode::TimerRemoved);
    assert!(removed
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::ActionRemoved));
}

#[test]
fn timer_change_closes_over_action_semantics_and_stable_recompile_is_empty() {
    let before = compile(&source(Some("activates-at"), true));
    let stable = compile(&source(Some("activates-at"), true));
    let unchanged = compiled_registry_change_set(&before, &stable, PRIOR_PACKAGE);
    assert!(unchanged.changes.is_empty(), "{:#?}", unchanged.changes);

    let action_changed = compile(&source(Some("activates-at"), false));
    let changes = compiled_registry_change_set(&before, &action_changed, PRIOR_PACKAGE);
    assert_timer_change(&changes, CompiledRegistryChangeCode::TimerChanged);
    assert!(changes
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::ActionChanged));
    assert_eq!(
        changes
            .changes
            .iter()
            .filter(|change| change.target.kind == CompiledRegistryChangeTargetKind::Timer)
            .count(),
        1,
        "{:#?}",
        changes.changes
    );
}

#[test]
fn serialized_timer_change_uses_the_closed_timer_vocabulary() {
    let before = compile(&source(None, true));
    let after = compile(&source(Some("activates-at"), true));
    let changes = compiled_registry_change_set(&before, &after, PRIOR_PACKAGE);
    let timer = changes
        .changes
        .iter()
        .find(|change| change.code == CompiledRegistryChangeCode::TimerAdded)
        .expect("timer addition is explicit");
    assert_eq!(
        serde_json::to_value(timer).expect("timer change serializes"),
        json!({
            "class":"access-or-disclosure-change",
            "code":"timer-added",
            "target":{"kind":"timer","recordTypeId":"contact","memberId":"activate"}
        })
    );
}

fn assert_timer_change(changes: &CompiledRegistryChangeSet, code: CompiledRegistryChangeCode) {
    let timer = changes
        .changes
        .iter()
        .find(|change| change.code == code)
        .unwrap_or_else(|| panic!("{code:?} is explicit: {:#?}", changes.changes));
    assert_eq!(
        timer.class,
        CompiledRegistryChangeClass::AccessOrDisclosureChange
    );
    assert_eq!(timer.target.kind, CompiledRegistryChangeTargetKind::Timer);
    assert_eq!(timer.target.record_type_id.as_deref(), Some("contact"));
    assert_eq!(timer.target.member_id.as_deref(), Some("activate"));
    assert!(
        change_set_to_applicable_migration_plan(changes).is_err(),
        "autonomous timer policy changes require reviewed activation"
    );
}

fn compile(source: &Value) -> CompiledRegistry {
    let project = parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).unwrap()
}

fn source(timer_at: Option<&str>, effect_value: bool) -> Value {
    let mut source = json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
        "kind":"BRegProject",
        "project":{
            "id":"timer-package", "version":"1", "defaultLanguage":"en",
            "canonicalBaseIri":"https://timer-package.example.test"
        },
        "datasets":[{"id":"test-dataset"}],
        "recordTypes":{"contact": { "primaryDataset":"test-dataset", "route":"contacts",
            "mutationMode":"mutable",
            "fields":[
                {"id":"active","type":"boolean","classification":"internal"},
                {"id":"processed","type":"boolean","classification":"internal"},
                {"id":"activates-at","type":"timestamp","classification":"internal"},
                {"id":"alternate-activates-at","type":"timestamp","classification":"internal"},
                {"id":"activation-window-end","type":"timestamp","classification":"internal"},
                {"id":"activation-revision","type":"uuid","classification":"internal"}
            ]
        }}
    });
    let Some(timer_at) = timer_at else {
        return source;
    };
    source["recordTypes"]["contact"]["timers"] = json!([{
        "id":"activate", "at":timer_at,
        "notAfter":"activation-window-end", "rearmOn":"activation-revision",
        "when":{"type":"fields","equals":{"active":false}},
        "invoke":"activate-contact",
        "input":{"contact":{"fromRecordId":true}}
    }]);
    source["timerGrants"] = json!([{"recordType":"contact","timer":"activate"}]);
    source["actions"] = json!([{
        "id":"activate-contact", "execution":{"mode":"immediate"},
        "inputs":[{
            "id":"contact", "type":"reference", "target":"contact",
            "required":true, "classification":"internal"
        }],
        "plan":{"type":"fixed","effects":[{
            "id":"mark-processed", "target":{"fromInput":"contact"},
            "operation":"patch", "set":{"processed":{"value":effect_value}}
        }]}
    }]);
    source
}

#[cfg(feature = "runtime")]
#[test]
fn timer_activation_preview_is_structural_value_free_and_change_specific() {
    use crate::timer_activation_preview::{
        timer_activation_preview_definitions, TimerActivationChange, TimerBackfill,
        TimerHistoricalRecords, TimerMigrationField, TimerRemovalFence, TimerSuccessorEvaluation,
    };

    let without_timer = compile(&source(None, true));
    let primary = compile(&source_with_effect_input("activates-at"));
    let alternate = compile(&source_with_effect_input("alternate-activates-at"));
    let migrated_fields = BTreeSet::from([
        ("contact".to_owned(), "activation-revision".to_owned()),
        ("contact".to_owned(), "active".to_owned()),
        ("other".to_owned(), "activation-revision".to_owned()),
    ]);
    let cases = [
        (
            &without_timer,
            &primary,
            TimerActivationChange::Added,
            TimerSuccessorEvaluation::HistoricalRecordsUnarmed,
            TimerRemovalFence::NotApplicable,
        ),
        (
            &primary,
            &alternate,
            TimerActivationChange::Changed,
            TimerSuccessorEvaluation::UnknownUntilRefresh,
            TimerRemovalFence::NotApplicable,
        ),
        (
            &primary,
            &without_timer,
            TimerActivationChange::Removed,
            TimerSuccessorEvaluation::RemovedNoExecutionFenced,
            TimerRemovalFence::Retained,
        ),
        (
            &primary,
            &primary,
            TimerActivationChange::EffectInputMigration,
            TimerSuccessorEvaluation::UnknownUntilRefresh,
            TimerRemovalFence::NotApplicable,
        ),
    ];
    for (before, after, expected_change, expected_evaluation, expected_fence) in cases {
        let changes = compiled_registry_change_set(before, after, PRIOR_PACKAGE);
        let definitions = timer_activation_preview_definitions(
            &CompiledRegistryMigrationBaseline::from_compiled(PRIOR_PACKAGE, before),
            after,
            &changes.changes,
            &migrated_fields,
        )
        .expect("verified timer changes produce a preview");
        assert_eq!(definitions.len(), 1, "{definitions:#?}");
        let preview = &definitions[0];
        assert_eq!(preview.record_type, "contact");
        assert_eq!(preview.timer, "activate");
        assert_eq!(preview.change, expected_change);
        assert_eq!(preview.successor_evaluation, expected_evaluation);
        assert_eq!(preview.historical_records, TimerHistoricalRecords::Unarmed);
        assert_eq!(preview.backfill, TimerBackfill::Unavailable);
        assert_eq!(preview.removal_fence, expected_fence);
        assert_eq!(
            preview.effect_shaping_migration_fields,
            [TimerMigrationField {
                record_type: "contact".to_owned(),
                field: "activation-revision".to_owned(),
            }]
        );
        assert_eq!(
            preview
                .predecessor_revisions
                .as_ref()
                .map(|revisions| revisions.definition.as_str()),
            before.entities()["contact"]
                .timers
                .get("activate")
                .map(|timer| timer.definition_revision.as_str())
        );
        assert_eq!(
            preview
                .successor_revisions
                .as_ref()
                .map(|revisions| revisions.definition.as_str()),
            after.entities()["contact"]
                .timers
                .get("activate")
                .map(|timer| timer.definition_revision.as_str())
        );
        let rendered = serde_json::to_string(preview).expect("preview serializes");
        assert!(!rendered.contains("UPDATE "));
        assert!(!rendered.contains("preview-secret-value"));
    }

    let unchanged = compiled_registry_change_set(&primary, &primary, PRIOR_PACKAGE);
    assert!(timer_activation_preview_definitions(
        &CompiledRegistryMigrationBaseline::from_compiled(PRIOR_PACKAGE, &primary),
        &primary,
        &unchanged.changes,
        &BTreeSet::new(),
    )
    .expect("stable recompilation previews")
    .is_empty());
}

#[cfg(feature = "runtime")]
#[test]
fn effect_input_migration_closure_is_record_type_qualified_and_get_only() {
    use crate::timer_activation_preview::{
        timer_activation_preview_definitions, TimerActivationChange, TimerMigrationField,
    };

    let registry = compile(&source_with_secondary_get());
    let changes = compiled_registry_change_set(&registry, &registry, PRIOR_PACKAGE);
    let definitions = timer_activation_preview_definitions(
        &CompiledRegistryMigrationBaseline::from_compiled(PRIOR_PACKAGE, &registry),
        &registry,
        &changes.changes,
        &BTreeSet::from([
            ("approval".to_owned(), "status".to_owned()),
            ("contact".to_owned(), "active".to_owned()),
        ]),
    )
    .expect("qualified current reads preview");
    assert_eq!(definitions.len(), 1, "{definitions:#?}");
    assert_eq!(
        definitions[0].change,
        TimerActivationChange::EffectInputMigration
    );
    assert_eq!(
        definitions[0].predecessor_revisions,
        definitions[0].successor_revisions
    );
    assert_eq!(
        definitions[0].effect_shaping_migration_fields,
        [TimerMigrationField {
            record_type: "approval".to_owned(),
            field: "status".to_owned(),
        }]
    );
}

#[cfg(feature = "runtime")]
fn source_with_effect_input(timer_at: &str) -> Value {
    let mut source = source(Some(timer_at), true);
    source["recordTypes"]["contact"]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"copied-activation-revision", "type":"uuid", "classification":"internal"
        }));
    source["recordTypes"]["contact"]["timers"][0]["input"]["activation-revision"] =
        json!({"fromField":"activation-revision"});
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"activation-revision", "type":"uuid", "required":true,
            "classification":"internal"
        }));
    source["actions"][0]["plan"]["effects"][0]["set"]["copied-activation-revision"] =
        json!({"fromInput":"activation-revision"});
    source
}

#[cfg(feature = "runtime")]
fn source_with_secondary_get() -> Value {
    let mut source = source(Some("activates-at"), true);
    source["recordTypes"].as_object_mut().unwrap().insert(
        "approval".to_owned(),
        json!({"primaryDataset":"test-dataset", "route":"approvals",
            "mutationMode":"mutable", "fields":[{
                "id":"status", "type":"string", "maximumLength":32,
                "classification":"internal"
            }]
        }),
    );
    source["recordTypes"]["contact"]["timers"][0]["input"]["approval"] =
        json!({"value":"11111111-1111-4111-8111-111111111111"});
    source["actions"][0]["inputs"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"approval", "type":"reference", "target":"approval", "required":true,
            "classification":"internal"
        }));
    source["actions"][0]["commitGuards"] = json!({"targets":[{
        "input":"approval", "field":"status", "equals":"approved"
    }]});
    source
}
