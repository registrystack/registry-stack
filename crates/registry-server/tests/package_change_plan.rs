// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

#[cfg(feature = "tooling")]
use std::fs;

use registry_platform_canonical_json::canonicalize_json;
use registry_server::compiler::{
    compile_project, compile_project_with_assets, module_digest, module_digest_with_assets,
    CompileProfile,
};
use registry_server::contract::{parse_module_yaml, parse_project_yaml, ModuleAssetSource};
#[cfg(feature = "tooling")]
use registry_server::migration_plan::{
    ArtifactDigestBinding, ChunkCursorProtocol, ExternalBackupBinding, MigrationRehearsalReceipt,
    RehearsalFixture, RehearsalProofs, RehearsalRowAssertion, ReviewedChangeCover,
    ReviewedMigrationAssertionDescriptor, ReviewedMigrationDescriptor, ReviewedMigrationFile,
    ReviewedMigrationObject, ReviewedMigrationObjectKind, ReviewedMigrationRecovery,
    ReviewedMigrationSource, ReviewedMigrationStepDescriptor,
};
use registry_server::package::{
    change_set_to_applicable_migration_plan, compiled_registry_change_set,
    CompiledRegistryChangeClass, CompiledRegistryChangeCode, PackageBuildRequest,
    PackageMigrationPlanInput, PackageModuleSource, PackageSourceFile, SignaturePolicy,
};
#[cfg(feature = "tooling")]
use registry_server::package::{inspect_package_integrity, prepare_package, PreparedPackage};
use registry_server::CompiledRegistry;
#[cfg(feature = "tooling")]
use serde::Serialize;
#[cfg(feature = "tooling")]
use serde_json::json;
#[cfg(feature = "tooling")]
use sha2::{Digest, Sha256};

const INSTANCE: &str = "instance-under-test";
const DATABASE: &str = "database-under-test";
const SOURCE_REVISION: &str = "compiler-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: asset-list
    steps:
      - id: list-assets
        entity: asset
        accessProfile: reader
        claims: {principal: package-reader}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
const PRIOR_REVISION: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
#[cfg(feature = "tooling")]
const PRIOR_FINGERPRINT: &str =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";
#[cfg(feature = "tooling")]
const FINAL_FINGERPRINT: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
#[cfg(feature = "tooling")]
const SUMMARY_CANARY: &str = "summary-canary";
#[cfg(feature = "tooling")]
const SQL_CANARY: &str = "summary-sql-canary";

#[test]
fn new_optional_scalar_field_emits_only_closed_add_column() {
    let previous = compile_variant(Variant::Base, 1);
    let candidate = compile_variant(Variant::OptionalField, 2);

    let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
    assert_eq!(change_set.changes.len(), 1);
    assert_change(
        &change_set,
        CompiledRegistryChangeClass::CompatibleAdditive,
        CompiledRegistryChangeCode::FieldAddedOptional,
    );
    let plan = change_set_to_applicable_migration_plan(&change_set)
        .expect("optional field change is applicable");
    assert_eq!(plan.from_revision.as_deref(), Some(PRIOR_REVISION));
    assert_eq!(
        plan.prior_baseline
            .as_ref()
            .map(|baseline| baseline.package_revision.as_str()),
        Some(PRIOR_REVISION)
    );
    assert_eq!(plan.changes, change_set.changes);
    assert_eq!(plan.statements.len(), 2);
    assert_eq!(plan.statements[0].id, "entity.asset.field.color.column");
    assert!(plan.statements[0]
        .sql
        .starts_with("ALTER TABLE registry_data."));
    assert!(plan.statements[0].sql.contains(" ADD COLUMN "));
    assert!(plan.statements[0].sql.contains("varchar(16)"));
    assert!(!plan.statements[0].sql.contains("CREATE TABLE"));
    assert_eq!(plan.statements[1].id, "entity.asset.source-view");
    assert!(plan.statements[1]
        .sql
        .starts_with("CREATE OR REPLACE VIEW "));

    let rendered_changes = serde_json::to_string(&change_set.changes).expect("changes serialize");
    for forbidden in [
        "registry_data",
        "CREATE TABLE",
        "ALTER TABLE",
        "source/",
        "f_",
    ] {
        assert!(
            !rendered_changes.contains(forbidden),
            "change diagnostics must stay value-free"
        );
    }
}

#[test]
fn new_entity_plan_uses_complete_candidate_ddl_in_dependency_order() {
    let previous = compile_variant(Variant::Base, 1);
    let candidate = compile_variant(Variant::NewEntity, 2);
    let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
    assert_change(
        &change_set,
        CompiledRegistryChangeClass::CompatibleAdditive,
        CompiledRegistryChangeCode::EntityAdded,
    );
    let plan = change_set_to_applicable_migration_plan(&change_set)
        .expect("new entity change is applicable");
    let expected = candidate
        .ddl()
        .statements
        .iter()
        .filter(|statement| statement.id.starts_with("entity.placement."))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(plan.statements, expected);
    assert!(plan
        .statements
        .first()
        .is_some_and(|statement| statement.id == "entity.placement.table"));
    assert!(plan
        .statements
        .iter()
        .any(|statement| statement.id == "entity.placement.field.asset.reference"));
    assert!(plan
        .statements
        .iter()
        .any(|statement| statement.id == "entity.placement.rls.force"));
}

#[test]
fn new_reference_constraint_and_index_are_supported_additive_statements() {
    let previous = compile_variant(Variant::Base, 1);
    let candidate = compile_variant(Variant::ReferenceConstraintIndex, 2);
    let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
    assert_change(
        &change_set,
        CompiledRegistryChangeClass::CompatibleAdditive,
        CompiledRegistryChangeCode::FieldAddedOptional,
    );
    assert_change(
        &change_set,
        CompiledRegistryChangeClass::CompatibleAdditive,
        CompiledRegistryChangeCode::ConstraintAdded,
    );
    assert_change(
        &change_set,
        CompiledRegistryChangeClass::CompatibleAdditive,
        CompiledRegistryChangeCode::IndexAdded,
    );
    let plan = change_set_to_applicable_migration_plan(&change_set)
        .expect("reference, constraint, and index additions are applicable");
    let ids = plan
        .statements
        .iter()
        .map(|statement| statement.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec![
            "entity.asset.field.site.column",
            "entity.asset.field.site.reference",
            "entity.asset.constraint.code-unique",
            "entity.asset.index.code-idx",
            "entity.asset.source-view",
        ]
    );
}

#[test]
fn non_additive_changes_are_classified_and_cannot_create_applicable_plans() {
    for (previous_variant, candidate_variant, class, code) in [
        (
            Variant::Base,
            Variant::RequiredField,
            CompiledRegistryChangeClass::DataBackfillRequired,
            CompiledRegistryChangeCode::FieldAddedRequired,
        ),
        (
            Variant::Base,
            Variant::FieldRemoved,
            CompiledRegistryChangeClass::DestructiveOrIrreversible,
            CompiledRegistryChangeCode::FieldRemoved,
        ),
        (
            Variant::Base,
            Variant::TypeChanged,
            CompiledRegistryChangeClass::DestructiveOrIrreversible,
            CompiledRegistryChangeCode::FieldTypeChanged,
        ),
        (
            Variant::Base,
            Variant::RouteChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            CompiledRegistryChangeCode::EntityRouteChanged,
        ),
        (
            Variant::Base,
            Variant::EntityClassificationChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            CompiledRegistryChangeCode::EntityClassificationChanged,
        ),
        (
            Variant::Base,
            Variant::ClassificationChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            CompiledRegistryChangeCode::FieldClassificationChanged,
        ),
        (
            Variant::Base,
            Variant::AuthorizationChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            CompiledRegistryChangeCode::AccessProfileChanged,
        ),
        (
            Variant::Base,
            Variant::MutationModeChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            CompiledRegistryChangeCode::EntityMutationModeChanged,
        ),
        (
            Variant::Base,
            Variant::TemporalChanged,
            CompiledRegistryChangeClass::DestructiveOrIrreversible,
            CompiledRegistryChangeCode::EntityTemporalChanged,
        ),
        (
            Variant::TemporalRoleBase,
            Variant::TemporalRoleChanged,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            CompiledRegistryChangeCode::FieldTemporalRoleChanged,
        ),
        (
            Variant::Base,
            Variant::RankRequired,
            CompiledRegistryChangeClass::DataBackfillRequired,
            CompiledRegistryChangeCode::FieldRequirednessChanged,
        ),
        (
            Variant::RankRequired,
            Variant::Base,
            CompiledRegistryChangeClass::DestructiveOrIrreversible,
            CompiledRegistryChangeCode::FieldRequirednessChanged,
        ),
        (
            Variant::ReferenceTargetBase,
            Variant::ReferenceTargetChanged,
            CompiledRegistryChangeClass::DestructiveOrIrreversible,
            CompiledRegistryChangeCode::ReferenceTargetChanged,
        ),
    ] {
        let previous = compile_variant(previous_variant, 1);
        let candidate = compile_variant(candidate_variant, 2);
        let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
        assert_change(&change_set, class, code);
        assert_eq!(change_set.migration_plan, None);
        assert!(change_set_to_applicable_migration_plan(&change_set).is_err());
    }
}

#[test]
fn complete_extension_surface_modules_are_order_independent() {
    let field_module = parse_module_yaml(br#"{"id":"field-extension","version":"1","extendEntities":[{"entity":"asset","fields":[{"id":"status","type":"string","maxLength":16,"classification":"internal"}],"constraints":[{"kind":"unique","id":"status-unique","fields":["status"]}],"indexes":[{"id":"status-idx","fields":["status"]}]}]}"#)
        .expect("field extension parses");
    let event_module = parse_module_yaml(br#"{"id":"event-extension","version":"1","extendEntities":[{"entity":"asset","accessProfiles":[{"id":"auditor","principalClaim":"principal","operations":["get","list"],"readableFields":["code","status"],"writableFields":[]}],"events":[{"id":"asset-created","trigger":"created","projection":["code","status"],"webhook":{"destinationId":"package-change-events"}}]}],"entities":[{"id":"site","route":"sites","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}]}]}"#)
        .expect("event extension parses");
    let project_bytes = format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en"}},"package":{{"environment":"local","instanceId":"{INSTANCE}","sequence":2,"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"name":"Package Test Publisher"}}}},"dataset":{{"title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}}},"entities":[{{"id":"asset","route":"assets","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":8,"classification":"internal"}}]}}],"accessProfiles":[{{"id":"reader","default":true,"principalClaim":"principal","grants":[{{"entity":"asset","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}}]}}],"modules":[{{"id":"field-extension","version":"1","digest":"{}"}},{{"id":"event-extension","version":"1","digest":"{}"}}]}}"#,
        module_digest(&field_module),
        module_digest(&event_module)
    );
    let project = parse_project_yaml(project_bytes.as_bytes()).expect("project parses");
    let first = compile_project(
        &project,
        &[field_module.clone(), event_module.clone()],
        CompileProfile::Production,
    )
    .expect("extension modules compile");
    let second = compile_project(
        &project,
        &[event_module, field_module],
        CompileProfile::Production,
    )
    .expect("extension modules compile in reverse input order");

    let first_bytes = canonicalize_json(&serde_json::to_value(&first).expect("first serializes"))
        .expect("first canonicalizes");
    let second_bytes =
        canonicalize_json(&serde_json::to_value(&second).expect("second serializes"))
            .expect("second canonicalizes");
    assert_eq!(first_bytes, second_bytes);
    let asset = &first.entities()["asset"];
    assert!(asset.fields.contains_key("status"));
    assert!(asset.constraints.contains_key("status-unique"));
    assert!(asset.indexes.contains_key("status-idx"));
    assert!(asset.access_profiles.contains_key("auditor"));
    assert!(asset.events.contains_key("asset-created"));
    assert!(first.entities().contains_key("site"));
}

#[test]
fn equivalent_reordered_inputs_produce_stable_change_and_statement_inventory() {
    let previous = compile_variant(Variant::Base, 1);
    let candidate = compile_variant(Variant::ReferenceConstraintIndex, 2);
    let reordered = compile_variant(Variant::ReferenceConstraintIndexReordered, 2);
    let first = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
    let second = compiled_registry_change_set(&previous, &reordered, PRIOR_REVISION);
    let first_bytes =
        canonicalize_json(&serde_json::to_value(&first.changes).expect("first changes serialize"))
            .expect("first changes canonicalize");
    let second_bytes = canonicalize_json(
        &serde_json::to_value(&second.changes).expect("second changes serialize"),
    )
    .expect("second changes canonicalize");
    assert_eq!(first_bytes, second_bytes);
    let first_statement_ids = first
        .migration_plan
        .as_ref()
        .expect("first additive migration plan exists")
        .statements
        .iter()
        .map(|statement| statement.id.as_str())
        .collect::<Vec<_>>();
    let second_statement_ids = second
        .migration_plan
        .as_ref()
        .expect("second additive migration plan exists")
        .statements
        .iter()
        .map(|statement| statement.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(first_statement_ids, second_statement_ids);
}

#[test]
fn generated_successor_plan_passes_package_validation_with_prior_revision() {
    let previous_source = source_for_variant(Variant::Base, 1);
    let previous_package = registry_server::package::prepare_package(build_request(
        1,
        None,
        previous_source.project_bytes,
        previous_source.module_bytes,
        PackageMigrationPlanInput::InitialCompiledDdl,
    ))
    .expect("initial package prepares");
    let prior_revision = previous_package.package_revision().to_owned();

    let previous = compile_variant(Variant::Base, 1);
    let candidate = compile_variant(Variant::ReferenceConstraintIndex, 2);
    let expected = compiled_registry_change_set(&previous, &candidate, &prior_revision);
    let expected_plan = change_set_to_applicable_migration_plan(&expected)
        .expect("candidate additive plan is applicable");

    let candidate_source = source_for_variant(Variant::ReferenceConstraintIndex, 2);
    let successor = registry_server::package::prepare_package(build_request(
        2,
        Some(&prior_revision),
        candidate_source.project_bytes,
        candidate_source.module_bytes,
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(previous),
        },
    ))
    .expect("successor closed plan validates");
    assert_eq!(
        successor.manifest().migration_plan.from_revision.as_deref(),
        Some(prior_revision.as_str())
    );
    assert_eq!(successor.manifest().migration_plan, expected_plan);
}

#[test]
fn derived_sql_asset_bytes_change_revisions_and_emit_generated_view_replacement() {
    let previous_source = derived_source_for_sql(
        1,
        b"SELECT a.id AS id, a.code AS summary FROM registry_source.asset a",
    );
    let previous = compile_derived_source(&previous_source);
    let previous_package = registry_server::package::prepare_package(derived_build_request(
        &previous_source,
        1,
        None,
        None,
    ))
    .expect("initial derived package prepares");

    let candidate_source = derived_source_for_sql(
        2,
        b"SELECT a.id AS id, (a.code) AS summary FROM registry_source.asset a",
    );
    let candidate = compile_derived_source(&candidate_source);
    let successor = registry_server::package::prepare_package(derived_build_request(
        &candidate_source,
        2,
        Some(&previous),
        Some(previous_package.package_revision()),
    ))
    .expect("successor derived package prepares");

    assert_ne!(
        previous.module_closure()[0].digest,
        candidate.module_closure()[0].digest
    );
    assert_ne!(previous.revision(), candidate.revision());
    assert_ne!(
        previous_package.package_revision(),
        successor.package_revision()
    );
    assert!(successor
        .file_bytes()
        .contains_key("source/modules/core/sql/summary.sql"));
    assert!(successor.manifest().files.iter().any(|entry| {
        entry.path == "source/modules/core/sql/summary.sql"
            && entry.role == registry_server::package::PackageFileRole::SourceModuleAsset
    }));

    let change_set =
        compiled_registry_change_set(&previous, &candidate, previous_package.package_revision());
    assert_change(
        &change_set,
        CompiledRegistryChangeClass::CompatibleAdditive,
        CompiledRegistryChangeCode::DerivedRelationChanged,
    );
    let plan = change_set_to_applicable_migration_plan(&change_set)
        .expect("same-contract SQL replacement is generated");
    assert!(plan.statements.iter().any(|statement| {
        statement.id == "entity.asset.derived.summary.view"
            && statement.sql.starts_with("CREATE OR REPLACE VIEW ")
    }));

    let source_asset_entry = successor
        .manifest()
        .files
        .iter()
        .find(|entry| entry.path == "source/modules/core/sql/summary.sql")
        .expect("asset file entry exists");
    assert!(source_asset_entry.sha256.starts_with("sha256:"));
}

#[test]
fn oversized_derived_sql_asset_is_refused_before_compilation() {
    let mut source = derived_source_for_sql(
        1,
        b"SELECT a.id AS id, a.code AS summary FROM registry_source.asset a",
    );
    source.sql = vec![b'x'; 256 * 1024 + 1];
    let module = parse_module_yaml(&source.module_bytes).expect("derived module parses");
    source.project_bytes = project_bytes(
        1,
        &module_digest_with_assets(
            &module,
            &[ModuleAssetSource {
                module: Some("core".to_owned()),
                path: "sql/summary.sql".to_owned(),
                bytes: source.sql.clone(),
            }],
        ),
    );

    assert_eq!(
        registry_server::package::prepare_package(derived_build_request(&source, 1, None, None))
            .err(),
        Some(registry_server::package::PackageError::Derivation)
    );
}

#[cfg(feature = "tooling")]
#[test]
fn metadata_only_reviewed_migration_covers_non_sql_surface_without_dummy_sql() {
    let previous = compile_variant(Variant::MetadataOnlyBase, 1);
    let candidate = compile_variant(Variant::MetadataOnlyChanged, 2);
    let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
    for code in [
        CompiledRegistryChangeCode::EntityRouteChanged,
        CompiledRegistryChangeCode::EntityMutationModeChanged,
        CompiledRegistryChangeCode::EntityClassificationChanged,
        CompiledRegistryChangeCode::EntityAccessRequirementsChanged,
        CompiledRegistryChangeCode::FieldClassificationChanged,
        CompiledRegistryChangeCode::FieldTemporalRoleChanged,
        CompiledRegistryChangeCode::AccessProfileChanged,
        CompiledRegistryChangeCode::RouteChanged,
        CompiledRegistryChangeCode::EventChanged,
    ] {
        assert_change(
            &change_set,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            code,
        );
    }
    assert!(change_set_to_applicable_migration_plan(&change_set).is_err());

    let source = source_for_variant(Variant::MetadataOnlyChanged, 2);
    let reviewed = prepare_package(build_request(
        2,
        Some(PRIOR_REVISION),
        source.project_bytes,
        source.module_bytes,
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(previous),
            prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
            migrations: vec![metadata_only_source(&candidate)],
        },
    ))
    .expect("metadata-only reviewed successor prepares without SQL steps");
    assert!(reviewed.manifest().migration_plan.statements.is_empty());
    assert_eq!(
        reviewed.manifest().migration_plan.reviewed_descriptors,
        ["modules/core/migrations/metadata-only/descriptor.json"]
    );
    for path in reviewed.file_bytes().keys() {
        assert!(
            !path.contains("/steps/"),
            "metadata-only review used step SQL"
        );
        assert!(
            !path.contains("/assertions/"),
            "metadata-only review used assertion SQL"
        );
        assert!(
            !path.contains("/fixtures/"),
            "metadata-only review used fixture data"
        );
    }
}

#[cfg(feature = "tooling")]
#[test]
fn reference_target_change_can_be_reviewed_through_compiler_owned_fk_constraint() {
    let previous = compile_variant(Variant::ReferenceTargetBase, 1);
    let candidate = compile_variant(Variant::ReferenceTargetChanged, 2);
    let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
    assert_change(
        &change_set,
        CompiledRegistryChangeClass::DestructiveOrIrreversible,
        CompiledRegistryChangeCode::ReferenceTargetChanged,
    );
    assert!(change_set_to_applicable_migration_plan(&change_set).is_err());

    let source = source_for_variant(Variant::ReferenceTargetChanged, 2);
    let reviewed = prepare_package(build_request(
        2,
        Some(PRIOR_REVISION),
        source.project_bytes,
        source.module_bytes,
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(previous),
            prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
            migrations: vec![reference_target_source(&candidate)],
        },
    ))
    .expect("reference target reviewed successor prepares");
    assert_eq!(
        reviewed.manifest().migration_plan.reviewed_descriptors,
        ["modules/core/migrations/reference-target/descriptor.json"]
    );
}

#[cfg(feature = "tooling")]
#[test]
fn inspected_migration_summaries_are_exact_deterministic_and_value_free() {
    let initial_source = source_for_variant(Variant::Base, 1);
    let initial = prepare_package(build_request(
        1,
        None,
        initial_source.project_bytes,
        initial_source.module_bytes,
        PackageMigrationPlanInput::InitialCompiledDdl,
    ))
    .expect("initial package prepares");
    let inspected_initial = inspect_prepared(&initial);
    let initial_summary = inspected_initial.migration_summary();
    let initial_statement_count = initial_summary.generated_statement_count();
    assert!(initial_statement_count > 0);
    assert_eq!(
        serde_json::to_value(initial_summary).expect("initial summary serializes"),
        json!({
            "planKind": "initial",
            "hasPriorRevision": false,
            "hasPriorBaseline": false,
            "changeCount": 0,
            "changeCounts": {
                "compatibleAdditive": 0,
                "dataBackfillRequired": 0,
                "accessOrDisclosureChange": 0,
                "destructiveOrIrreversible": 0,
                "unsupported": 0,
            },
            "generatedStatementCount": initial_statement_count,
            "reviewedMigrations": [],
        })
    );

    let additive_source = source_for_variant(Variant::OptionalField, 2);
    let additive = prepare_package(build_request(
        2,
        Some(PRIOR_REVISION),
        additive_source.project_bytes,
        additive_source.module_bytes,
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(compile_variant(Variant::Base, 1)),
        },
    ))
    .expect("additive package prepares");
    let inspected_additive = inspect_prepared(&additive);
    assert_eq!(
        serde_json::to_value(inspected_additive.migration_summary())
            .expect("additive summary serializes"),
        json!({
            "planKind": "compatible_additive",
            "hasPriorRevision": true,
            "hasPriorBaseline": true,
            "changeCount": 1,
            "changeCounts": {
                "compatibleAdditive": 1,
                "dataBackfillRequired": 0,
                "accessOrDisclosureChange": 0,
                "destructiveOrIrreversible": 0,
                "unsupported": 0,
            },
            "generatedStatementCount": 2,
            "reviewedMigrations": [],
        })
    );

    let reviewed = reviewed_package_with_canaries();
    let first = inspect_prepared(&reviewed);
    let second = inspect_prepared(&reviewed);
    let expected = json!({
        "planKind": "reviewed",
        "hasPriorRevision": true,
        "hasPriorBaseline": true,
        "changeCount": 2,
        "changeCounts": {
            "compatibleAdditive": 1,
            "dataBackfillRequired": 1,
            "accessOrDisclosureChange": 0,
            "destructiveOrIrreversible": 0,
            "unsupported": 0,
        },
        "generatedStatementCount": 3,
        "reviewedMigrations": [{
            "changeClass": "data_backfill_required",
            "recovery": "exact_target_resume",
            "lockTimeoutMs": 10_000,
            "statementTimeoutMs": 60_000,
            "transactionalStepCount": 0,
            "chunkedStepCount": 1,
            "preAssertionCount": 1,
            "postAssertionCount": 1,
            "backupRequired": false,
            "chunkedStepBounds": {
                "minimumChunkSize": 100,
                "maximumChunkSize": 100,
                "maximumTotalRows": 1_000,
            },
        }],
    });
    assert_eq!(
        serde_json::to_value(first.migration_summary()).expect("reviewed summary serializes"),
        expected
    );
    let first_bytes =
        serde_json::to_vec(first.migration_summary()).expect("first summary serializes");
    let second_bytes =
        serde_json::to_vec(second.migration_summary()).expect("second summary serializes");
    assert_eq!(first_bytes, second_bytes, "summary bytes are deterministic");

    let candidate = compile_variant(Variant::RequiredAndOptionalFields, 2);
    let entity = &candidate.entities()["asset"];
    let rendered = String::from_utf8(first_bytes).expect("summary JSON is UTF-8");
    let debug = format!("{:?}", first.migration_summary());
    for forbidden in [
        SUMMARY_CANARY,
        SQL_CANARY,
        "step-canary",
        "pre-canary",
        "post-canary",
        "fixture-canary",
        "fixture-content-canary",
        "UPDATE registry_data",
        "SELECT pg_catalog",
        INSTANCE,
        DATABASE,
        SOURCE_REVISION,
        PRIOR_REVISION,
        PRIOR_FINGERPRINT,
        "source/registry.yaml",
        "asset",
        "batch",
        entity.physical_table.as_str(),
        entity.fields["batch"].physical_name.as_str(),
    ] {
        assert!(!rendered.contains(forbidden), "JSON leaked {forbidden}");
        assert!(!debug.contains(forbidden), "Debug leaked {forbidden}");
    }
}

#[cfg(feature = "tooling")]
#[test]
fn tampered_package_never_returns_a_migration_summary_or_canary() {
    let source = source_for_variant(Variant::Base, 1);
    let prepared = prepare_package(build_request(
        1,
        None,
        source.project_bytes,
        source.module_bytes,
        PackageMigrationPlanInput::InitialCompiledDdl,
    ))
    .expect("initial package prepares");
    let root = tempfile::Builder::new()
        .prefix("registry-package-summary-tamper-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("temporary package parent creates");
    let package = root.path().join("package");
    prepared
        .publish_to_directory(&package, Vec::new())
        .expect("package publishes");
    let manifest = package.join("package.json");
    let mut bytes = fs::read(&manifest).expect("manifest reads");
    bytes.extend_from_slice(SUMMARY_CANARY.as_bytes());
    fs::write(&manifest, bytes).expect("manifest tampers");

    let error = inspect_package_integrity(&package)
        .err()
        .expect("tampered package cannot return an inspected summary");
    let rendered = format!("{error:?}");
    assert!(!rendered.contains(SUMMARY_CANARY));
    assert!(!rendered.contains(package.to_string_lossy().as_ref()));
}

fn assert_change(
    change_set: &registry_server::package::CompiledRegistryChangeSet,
    class: CompiledRegistryChangeClass,
    code: CompiledRegistryChangeCode,
) {
    assert!(
        change_set
            .changes
            .iter()
            .any(|change| change.class == class && change.code == code),
        "expected {class:?}/{code:?} in {:#?}",
        change_set.changes
    );
}

#[derive(Clone, Copy)]
enum Variant {
    Base,
    OptionalField,
    RequiredField,
    #[cfg_attr(not(feature = "tooling"), allow(dead_code))]
    RequiredAndOptionalFields,
    NewEntity,
    ReferenceConstraintIndex,
    ReferenceConstraintIndexReordered,
    FieldRemoved,
    TypeChanged,
    RouteChanged,
    EntityClassificationChanged,
    ClassificationChanged,
    AuthorizationChanged,
    MutationModeChanged,
    TemporalChanged,
    TemporalRoleBase,
    TemporalRoleChanged,
    RankRequired,
    ReferenceTargetBase,
    ReferenceTargetChanged,
    #[cfg_attr(not(feature = "tooling"), allow(dead_code))]
    MetadataOnlyBase,
    #[cfg_attr(not(feature = "tooling"), allow(dead_code))]
    MetadataOnlyChanged,
}

struct SourceFixture {
    project_bytes: Vec<u8>,
    module_bytes: Vec<u8>,
}

struct DerivedSourceFixture {
    project_bytes: Vec<u8>,
    module_bytes: Vec<u8>,
    sql: Vec<u8>,
}

fn compile_variant(variant: Variant, sequence: u64) -> CompiledRegistry {
    let source = source_for_variant(variant, sequence);
    let module = parse_module_yaml(&source.module_bytes).expect("fixture module parses");
    let project = parse_project_yaml(&source.project_bytes).expect("fixture project parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("fixture compiles in production")
}

fn source_for_variant(variant: Variant, sequence: u64) -> SourceFixture {
    let module_bytes = module_bytes(variant);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses for digest");
    let digest = module_digest(&module);
    SourceFixture {
        project_bytes: project_bytes(sequence, &digest),
        module_bytes,
    }
}

fn project_bytes(sequence: u64, module_digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en"}},"package":{{"environment":"local","instanceId":"{INSTANCE}","sequence":{sequence},"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"name":"Package Test Publisher"}}}},"dataset":{{"title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    )
    .into_bytes()
}

fn derived_source_for_sql(sequence: u64, sql: &[u8]) -> DerivedSourceFixture {
    let module_bytes = br#"{"id":"core","version":"1","entities":[{"id":"asset","route":"assets","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"derived":[{"id":"summary","sql":"sql/summary.sql","key":"id","fields":[{"id":"summary","type":"string","maxLength":16,"classification":"internal"}]}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code","summary"]}]}]}"#.to_vec();
    let module = parse_module_yaml(&module_bytes).expect("derived module parses");
    let digest = module_digest_with_assets(
        &module,
        &[ModuleAssetSource {
            module: Some("core".to_owned()),
            path: "sql/summary.sql".to_owned(),
            bytes: sql.to_vec(),
        }],
    );
    DerivedSourceFixture {
        project_bytes: project_bytes(sequence, &digest),
        module_bytes,
        sql: sql.to_vec(),
    }
}

fn compile_derived_source(source: &DerivedSourceFixture) -> CompiledRegistry {
    let project = parse_project_yaml(&source.project_bytes).expect("derived project parses");
    let module = parse_module_yaml(&source.module_bytes).expect("derived module parses");
    compile_project_with_assets(
        &project,
        &[module],
        &[ModuleAssetSource {
            module: Some("core".to_owned()),
            path: "sql/summary.sql".to_owned(),
            bytes: source.sql.clone(),
        }],
        CompileProfile::Production,
    )
    .expect("derived fixture compiles")
}

fn derived_build_request(
    source: &DerivedSourceFixture,
    sequence: u64,
    prior_registry: Option<&CompiledRegistry>,
    prior_revision: Option<&str>,
) -> PackageBuildRequest {
    let mut request = build_request(
        sequence,
        prior_revision,
        source.project_bytes.clone(),
        source.module_bytes.clone(),
        match prior_registry {
            Some(registry) => PackageMigrationPlanInput::Successor {
                prior_registry: Box::new(registry.clone()),
            },
            None => PackageMigrationPlanInput::InitialCompiledDdl,
        },
    );
    request.modules[0].assets = vec![PackageSourceFile {
        path: "sql/summary.sql".to_owned(),
        bytes: source.sql.clone(),
    }];
    request
}

fn module_bytes(variant: Variant) -> Vec<u8> {
    let asset = match variant {
        Variant::OptionalField => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"color","type":"string","maxLength":16,"classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::RequiredField => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"batch","type":"string","maxLength":16,"required":true,"classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::RequiredAndOptionalFields => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"batch","type":"string","maxLength":16,"required":true,"classification":"internal"},{"id":"color","type":"string","maxLength":16,"classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::ReferenceConstraintIndex => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"site","type":"reference","target":"site","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            r#","constraints":[{"kind":"unique","id":"code-unique","fields":["code"]}]"#,
            r#","indexes":[{"id":"code-idx","fields":["code"]}]"#,
            "",
        ),
        Variant::ReferenceConstraintIndexReordered => asset_entity(
            r#"{"id":"site","type":"reference","target":"site","classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"code","type":"string","maxLength":8,"classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["list","get","create"],"writableFields":["code"],"readableFields":["code"]"#,
            r#","constraints":[{"fields":["code"],"id":"code-unique","kind":"unique"}]"#,
            r#","indexes":[{"fields":["code"],"id":"code-idx"}]"#,
            "",
        ),
        Variant::FieldRemoved => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::TypeChanged => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"string","maxLength":8,"classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::RouteChanged => asset_entity(
            base_asset_fields(),
            r#""route":"equipment""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::EntityClassificationChanged => asset_entity(
            base_asset_fields(),
            r#""route":"assets","classification":"restricted""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::ClassificationChanged => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"restricted"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::AuthorizationChanged => asset_entity(
            base_asset_fields(),
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"subject","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::MutationModeChanged => asset_entity_with_mode(
            base_asset_fields(),
            r#""route":"assets""#,
            "mutable",
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::TemporalChanged => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"required":true,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"valid-from","type":"date","required":true,"classification":"internal"},{"id":"valid-to","type":"date","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code","valid-from","valid-to"],"writableFields":["code","valid-from","valid-to"]"#,
            r#","constraints":[{"kind":"temporal-non-overlap","id":"code-time","scopeFields":["code"],"startField":"valid-from","endField":"valid-to"}]"#,
            "",
            r#","temporal":{"startField":"valid-from","endField":"valid-to","scopeFields":["code"]}"#,
        ),
        Variant::TemporalRoleBase => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"valid-from","type":"date","required":true,"classification":"internal"},{"id":"valid-to","type":"date","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code","valid-from","valid-to"],"writableFields":["code","valid-from","valid-to"]"#,
            "",
            "",
            "",
        ),
        Variant::TemporalRoleChanged => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"valid-from","type":"date","required":true,"classification":"internal","validTimeRole":"valid_from"},{"id":"valid-to","type":"date","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code","valid-from","valid-to"],"writableFields":["code","valid-from","valid-to"]"#,
            "",
            "",
            "",
        ),
        Variant::RankRequired => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","required":true,"classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::ReferenceTargetBase => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"home-site","type":"reference","target":"site","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::ReferenceTargetChanged => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"home-site","type":"reference","target":"location","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::MetadataOnlyBase => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"valid-from","type":"date","required":true,"classification":"internal"},{"id":"valid-to","type":"date","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code","valid-from","valid-to"],"writableFields":["code","valid-from","valid-to"]"#,
            "",
            "",
            r#","events":[{"id":"asset-created","trigger":"created","projection":["code"],"webhook":{"destinationId":"package-change-events"}}]"#,
        ),
        Variant::MetadataOnlyChanged => asset_entity_with_mode(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"restricted"},{"id":"valid-from","type":"date","required":true,"classification":"internal","validTimeRole":"valid_from"},{"id":"valid-to","type":"date","classification":"internal"}"#,
            r#""route":"equipment","classification":"restricted","accessRequirements":{"requiredScopes":["asset:read"]}"#,
            "mutable",
            r#""id":"reader","principalClaim":"subject","requiredScopes":["asset:read"],"operations":["create","get","list"],"readableFields":["code","valid-from","valid-to"],"writableFields":["code","valid-from","valid-to"]"#,
            "",
            "",
            r#","events":[{"id":"asset-created","trigger":"created","projection":["code","rank"],"webhook":{"destinationId":"package-change-events"}}]"#,
        ),
        Variant::Base | Variant::NewEntity => asset_entity(
            base_asset_fields(),
            r#""route":"assets""#,
            r#""id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
    };
    let placement = if matches!(variant, Variant::NewEntity) {
        format!(",{}", placement_entity())
    } else {
        String::new()
    };
    let location = if matches!(
        variant,
        Variant::ReferenceTargetBase | Variant::ReferenceTargetChanged
    ) {
        format!(",{}", location_entity())
    } else {
        String::new()
    };
    format!(
        r#"{{"id":"core","version":"1","entities":[{asset},{site}{location}{placement}]}}"#,
        site = site_entity()
    )
    .into_bytes()
}

fn base_asset_fields() -> &'static str {
    r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"}"#
}

fn asset_entity(
    fields: &str,
    route: &str,
    access: &str,
    constraints: &str,
    indexes: &str,
    temporal: &str,
) -> String {
    asset_entity_with_mode(
        fields,
        route,
        "create_only",
        access,
        constraints,
        indexes,
        temporal,
    )
}

fn asset_entity_with_mode(
    fields: &str,
    route: &str,
    mutation_mode: &str,
    access: &str,
    constraints: &str,
    indexes: &str,
    temporal: &str,
) -> String {
    format!(
        r#"{{"id":"asset",{route},"mutationMode":"{mutation_mode}","fields":[{fields}]{constraints}{indexes},"accessProfiles":[{{{access}}}]{temporal}}}"#
    )
}

fn site_entity() -> &'static str {
    r#"{"id":"site","route":"sites","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}]}"#
}

fn location_entity() -> &'static str {
    r#"{"id":"location","route":"locations","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}]}"#
}

fn placement_entity() -> &'static str {
    r#"{"id":"placement","route":"placements","mutationMode":"create_only","fields":[{"id":"asset","type":"reference","target":"asset","required":true,"classification":"internal"},{"id":"site","type":"reference","target":"site","required":true,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["asset","site"],"writableFields":["asset","site"]}]}"#
}

fn build_request(
    sequence: u64,
    prior_revision: Option<&str>,
    project_bytes: Vec<u8>,
    module_bytes: Vec<u8>,
    migration_plan: PackageMigrationPlanInput,
) -> PackageBuildRequest {
    PackageBuildRequest {
        environment: "local".to_owned(),
        instance_id: INSTANCE.to_owned(),
        database_id: DATABASE.to_owned(),
        sequence,
        prior_revision: prior_revision.map(str::to_owned),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint:
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes,
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.yaml".to_owned(),
            bytes: module_bytes,
            assets: Vec::new(),
        }],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan,
    }
}

#[cfg(feature = "tooling")]
fn metadata_only_source(candidate: &CompiledRegistry) -> ReviewedMigrationSource {
    let previous = compile_variant(Variant::MetadataOnlyBase, 1);
    let change_set = compiled_registry_change_set(&previous, candidate, PRIOR_REVISION);
    let mut covers = change_set
        .changes
        .iter()
        .filter(|change| change.class != CompiledRegistryChangeClass::CompatibleAdditive)
        .map(ReviewedChangeCover::from)
        .collect::<Vec<_>>();
    covers.sort();
    assert!(covers.iter().all(|cover| {
        change_set
            .changes
            .iter()
            .find(|change| change.code == cover.code && change.target == cover.target)
            .is_some_and(|change| {
                change.class == CompiledRegistryChangeClass::AccessOrDisclosureChange
            })
    }));

    let base = "modules/core/migrations/metadata-only";
    let descriptor = ReviewedMigrationDescriptor {
        id: "metadata-only".to_owned(),
        change_class: CompiledRegistryChangeClass::AccessOrDisclosureChange,
        covers,
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 10_000,
        statement_timeout_ms: 60_000,
        steps: Vec::new(),
        pre_assertions: Vec::new(),
        post_assertions: Vec::new(),
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
    };
    let descriptor_bytes = canonical(&descriptor);
    let receipt = MigrationRehearsalReceipt {
        prior_revision: PRIOR_REVISION.to_owned(),
        prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
        plan_sha256: digest(&descriptor_bytes),
        sql_sha256: Vec::new(),
        assertion_sha256: Vec::new(),
        fixture_inventory: Vec::new(),
        postgres_major: 16,
        row_assertions: Vec::new(),
        final_schema_fingerprint: FINAL_FINGERPRINT.to_owned(),
        proofs: RehearsalProofs {
            lock_timeout: true,
            chunk_resume: false,
            destructive_resume: false,
        },
    };
    ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: format!("{base}/descriptor.json"),
            bytes: descriptor_bytes,
        },
        files: vec![ReviewedMigrationFile {
            path: descriptor.rehearsal_receipt_path,
            bytes: canonical(&receipt),
        }],
    }
}

#[cfg(feature = "tooling")]
fn reference_target_source(candidate: &CompiledRegistry) -> ReviewedMigrationSource {
    let previous = compile_variant(Variant::ReferenceTargetBase, 1);
    let change_set = compiled_registry_change_set(&previous, candidate, PRIOR_REVISION);
    let change = change_set
        .changes
        .iter()
        .find(|change| change.code == CompiledRegistryChangeCode::ReferenceTargetChanged)
        .expect("reference target change is classified");
    let entity = &candidate.entities()["asset"];
    let field = &entity.fields["home-site"];
    let target = &candidate.entities()["location"];
    let constraint_name =
        &candidate.physical_names().entities["asset"].constraints["reference:home-site"];
    let base = "modules/core/migrations/reference-target";
    let drop_path = format!("{base}/steps/drop-reference.sql");
    let add_path = format!("{base}/steps/add-reference.sql");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let fixture_path = format!("{base}/fixtures/reference-target.jsonl");
    let drop_sql = format!(
        "ALTER TABLE registry_data.{} DROP CONSTRAINT {}",
        entity.physical_table, constraint_name
    )
    .into_bytes();
    let add_sql = format!(
        "ALTER TABLE registry_data.{} ADD CONSTRAINT {} FOREIGN KEY ({}) REFERENCES registry_data.{} (record_id) ON DELETE RESTRICT",
        entity.physical_table, constraint_name, field.physical_name, target.physical_table
    )
    .into_bytes();
    let assertion_sql = format!(
        "SELECT pg_catalog.count(*) >= 0 FROM registry_data.{}",
        entity.physical_table
    )
    .into_bytes();
    let fixture_bytes = b"{\"fixture\":\"reference-target\"}\n".to_vec();
    let object = ReviewedMigrationObject {
        schema: "registry_data".to_owned(),
        table: entity.physical_table.clone(),
        entity_id: "asset".to_owned(),
        kind: ReviewedMigrationObjectKind::Constraint,
        member_id: Some("reference:home-site".to_owned()),
        physical_name: constraint_name.clone(),
    };
    let descriptor = ReviewedMigrationDescriptor {
        id: "reference-target".to_owned(),
        change_class: change.class,
        covers: vec![ReviewedChangeCover::from(change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 10_000,
        statement_timeout_ms: 60_000,
        steps: vec![
            ReviewedMigrationStepDescriptor::TransactionalSql {
                id: "drop-reference".to_owned(),
                sql_path: drop_path.clone(),
                objects: vec![object.clone()],
                affected_rows: None,
            },
            ReviewedMigrationStepDescriptor::TransactionalSql {
                id: "add-reference".to_owned(),
                sql_path: add_path.clone(),
                objects: vec![object],
                affected_rows: None,
            },
        ],
        pre_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "pre".to_owned(),
            sql_path: pre_path.clone(),
        }],
        post_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "post".to_owned(),
            sql_path: post_path.clone(),
        }],
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: Some(format!("{base}/backup.json")),
    };
    let descriptor_bytes = canonical(&descriptor);
    let receipt = MigrationRehearsalReceipt {
        prior_revision: PRIOR_REVISION.to_owned(),
        prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
        plan_sha256: digest(&descriptor_bytes),
        sql_sha256: vec![
            ArtifactDigestBinding {
                path: drop_path.clone(),
                sha256: digest(&drop_sql),
            },
            ArtifactDigestBinding {
                path: add_path.clone(),
                sha256: digest(&add_sql),
            },
        ],
        assertion_sha256: vec![
            ArtifactDigestBinding {
                path: pre_path.clone(),
                sha256: digest(&assertion_sql),
            },
            ArtifactDigestBinding {
                path: post_path.clone(),
                sha256: digest(&assertion_sql),
            },
        ],
        fixture_inventory: vec![RehearsalFixture {
            id: "reference-target".to_owned(),
            path: fixture_path.clone(),
            sha256: digest(&fixture_bytes),
            row_count: 1,
        }],
        postgres_major: 16,
        row_assertions: Vec::new(),
        final_schema_fingerprint: FINAL_FINGERPRINT.to_owned(),
        proofs: RehearsalProofs {
            lock_timeout: true,
            chunk_resume: false,
            destructive_resume: true,
        },
    };
    let backup = ExternalBackupBinding {
        database_id: DATABASE.to_owned(),
        prior_revision: PRIOR_REVISION.to_owned(),
        prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
        sha256: "sha256:4444444444444444444444444444444444444444444444444444444444444444"
            .to_owned(),
        byte_length: 4096,
        created_at: "2026-08-30T00:00:00Z".to_owned(),
        max_age_seconds: 86_400,
    };
    let mut files = vec![
        ReviewedMigrationFile {
            path: drop_path,
            bytes: drop_sql,
        },
        ReviewedMigrationFile {
            path: add_path,
            bytes: add_sql,
        },
        ReviewedMigrationFile {
            path: pre_path,
            bytes: assertion_sql.clone(),
        },
        ReviewedMigrationFile {
            path: post_path,
            bytes: assertion_sql,
        },
        ReviewedMigrationFile {
            path: descriptor.rehearsal_receipt_path.clone(),
            bytes: canonical(&receipt),
        },
        ReviewedMigrationFile {
            path: descriptor.backup_binding_path.clone().expect("backup path"),
            bytes: canonical(&backup),
        },
        ReviewedMigrationFile {
            path: fixture_path,
            bytes: fixture_bytes,
        },
    ];
    files.sort_by(|left, right| left.path.cmp(&right.path));
    ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: format!("{base}/descriptor.json"),
            bytes: descriptor_bytes,
        },
        files,
    }
}

#[cfg(feature = "tooling")]
fn reviewed_package_with_canaries() -> PreparedPackage {
    let previous = compile_variant(Variant::Base, 1);
    let candidate = compile_variant(Variant::RequiredAndOptionalFields, 2);
    let source = reviewed_source_with_canaries(&previous, &candidate);
    let candidate_source = source_for_variant(Variant::RequiredAndOptionalFields, 2);
    prepare_package(build_request(
        2,
        Some(PRIOR_REVISION),
        candidate_source.project_bytes,
        candidate_source.module_bytes,
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(previous),
            prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
            migrations: vec![source],
        },
    ))
    .expect("reviewed package with canaries prepares")
}

#[cfg(feature = "tooling")]
fn reviewed_source_with_canaries(
    previous: &CompiledRegistry,
    candidate: &CompiledRegistry,
) -> ReviewedMigrationSource {
    let change_set = compiled_registry_change_set(previous, candidate, PRIOR_REVISION);
    let change = change_set
        .changes
        .iter()
        .find(|change| change.code == CompiledRegistryChangeCode::FieldAddedRequired)
        .expect("required field change is classified");
    let entity = &candidate.entities()["asset"];
    let field = &entity.fields["batch"];
    let base = format!("modules/core/migrations/{SUMMARY_CANARY}");
    let step_path = format!("{base}/steps/step-canary.sql");
    let pre_path = format!("{base}/assertions/pre-canary.sql");
    let post_path = format!("{base}/assertions/post-canary.sql");
    let fixture_path = format!("{base}/fixtures/fixture-canary.jsonl");
    let step_sql = format!(
        "UPDATE registry_data.{} SET {} = '{SQL_CANARY}' WHERE record_id = ANY($1::pg_catalog.uuid[])",
        entity.physical_table, field.physical_name
    )
    .into_bytes();
    let assertion_sql = format!(
        "SELECT pg_catalog.count(*) >= 0 FROM registry_data.{}",
        entity.physical_table
    )
    .into_bytes();
    let fixture_bytes = br#"{"fixture":"fixture-content-canary"}
"#
    .to_vec();
    let descriptor = ReviewedMigrationDescriptor {
        id: SUMMARY_CANARY.to_owned(),
        change_class: change.class,
        covers: vec![ReviewedChangeCover::from(change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 10_000,
        statement_timeout_ms: 60_000,
        steps: vec![ReviewedMigrationStepDescriptor::ChunkedBackfill {
            id: "step-canary".to_owned(),
            entity_id: "asset".to_owned(),
            sql_path: step_path.clone(),
            objects: vec![ReviewedMigrationObject {
                schema: "registry_data".to_owned(),
                table: entity.physical_table.clone(),
                entity_id: "asset".to_owned(),
                kind: ReviewedMigrationObjectKind::Field,
                member_id: Some("batch".to_owned()),
                physical_name: field.physical_name.clone(),
            }],
            cursor: ChunkCursorProtocol::RecordIdUuidArray,
            chunk_size: 100,
            max_total_rows: 1_000,
            lock_timeout_ms: 1_000,
            statement_timeout_ms: 10_000,
            exact_affected_rows: true,
        }],
        pre_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "pre-canary".to_owned(),
            sql_path: pre_path.clone(),
        }],
        post_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "post-canary".to_owned(),
            sql_path: post_path.clone(),
        }],
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
    };
    let descriptor_bytes = canonical(&descriptor);
    let receipt = MigrationRehearsalReceipt {
        prior_revision: PRIOR_REVISION.to_owned(),
        prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
        plan_sha256: digest(&descriptor_bytes),
        sql_sha256: vec![ArtifactDigestBinding {
            path: step_path.clone(),
            sha256: digest(&step_sql),
        }],
        assertion_sha256: vec![
            ArtifactDigestBinding {
                path: pre_path.clone(),
                sha256: digest(&assertion_sql),
            },
            ArtifactDigestBinding {
                path: post_path.clone(),
                sha256: digest(&assertion_sql),
            },
        ],
        fixture_inventory: vec![RehearsalFixture {
            id: "fixture-canary".to_owned(),
            path: fixture_path.clone(),
            sha256: digest(&fixture_bytes),
            row_count: 1,
        }],
        postgres_major: 16,
        row_assertions: vec![RehearsalRowAssertion {
            step_id: "step-canary".to_owned(),
            affected_rows: 10,
        }],
        final_schema_fingerprint:
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
        proofs: RehearsalProofs {
            lock_timeout: true,
            chunk_resume: true,
            destructive_resume: false,
        },
    };
    let mut files = vec![
        ReviewedMigrationFile {
            path: step_path,
            bytes: step_sql,
        },
        ReviewedMigrationFile {
            path: pre_path,
            bytes: assertion_sql.clone(),
        },
        ReviewedMigrationFile {
            path: post_path,
            bytes: assertion_sql,
        },
        ReviewedMigrationFile {
            path: descriptor.rehearsal_receipt_path.clone(),
            bytes: canonical(&receipt),
        },
        ReviewedMigrationFile {
            path: fixture_path,
            bytes: fixture_bytes,
        },
    ];
    files.sort_by(|left, right| left.path.cmp(&right.path));
    ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: format!("{base}/descriptor.json"),
            bytes: descriptor_bytes,
        },
        files,
    }
}

#[cfg(feature = "tooling")]
fn inspect_prepared(
    prepared: &PreparedPackage,
) -> registry_server::package::IntegrityInspectedPackage {
    let root = tempfile::Builder::new()
        .prefix("registry-package-summary-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("temporary package parent creates");
    let package = root.path().join("package");
    prepared
        .publish_to_directory(&package, Vec::new())
        .expect("package publishes");
    inspect_package_integrity(&package).expect("package inspects")
}

#[cfg(feature = "tooling")]
fn canonical(value: &impl Serialize) -> Vec<u8> {
    canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes")
}

#[cfg(feature = "tooling")]
fn digest(bytes: &[u8]) -> String {
    let value = Sha256::digest(bytes);
    let mut rendered = String::with_capacity(value.len() * 2 + 7);
    rendered.push_str("sha256:");
    for byte in value {
        use std::fmt::Write as _;

        write!(&mut rendered, "{byte:02x}").expect("digest writes");
    }
    rendered
}
