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
    change_set_to_applicable_migration_plan, compiled_registry_change_set, derive_package_revision,
    prepare_package_with_project_assets, CompiledRegistryChangeClass, CompiledRegistryChangeCode,
    PackageBuildRequest, PackageEnvelope, PackageError, PackageFileRole, PackageMigrationPlanInput,
    PackageModuleSource, PackageSourceFile, SignaturePolicy, MAX_RHAI_PLANNER_SOURCE_BYTES,
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
const RHAI_PLANNER_CANARY: &str = "rhai-package-source-canary";

#[cfg(feature = "tooling")]
#[test]
fn project_rhai_planner_package_is_deterministic_and_rederives_exact_source() {
    let request = project_planner_build_request();
    let asset = PackageSourceFile {
        path: "planners/request.rhai".to_owned(),
        bytes: project_planner_script().to_vec(),
    };
    let first = prepare_package_with_project_assets(request.clone(), vec![asset.clone()])
        .expect("declared project planner packages");
    let second = prepare_package_with_project_assets(request.clone(), vec![asset.clone()])
        .expect("the same planner package rederives deterministically");
    assert_eq!(first.package_revision(), second.package_revision());
    assert_eq!(
        first.canonical_signed_bytes(),
        second.canonical_signed_bytes()
    );
    assert_eq!(
        first.manifest().sources.project_assets,
        ["source/project/planners/request.rhai"]
    );
    let planner_entry = first
        .manifest()
        .files
        .iter()
        .find(|entry| entry.path == "source/project/planners/request.rhai")
        .expect("planner source is in the signed closure");
    assert_eq!(
        planner_entry.role,
        PackageFileRole::SourceProjectPlannerScript
    );
    assert!(!String::from_utf8_lossy(first.canonical_signed_bytes()).contains(RHAI_PLANNER_CANARY));

    let compiled_planner = first.registry().entities()["request"]
        .change_request
        .as_ref()
        .and_then(|request| request.planner.as_ref())
        .expect("compiled planner exists");
    assert_eq!(compiled_planner.source_module, None);
    assert_eq!(compiled_planner.script_path, "planners/request.rhai");
    assert_eq!(
        compiled_planner.rhai_version,
        registry_server::change_request::CHANGE_REQUEST_PLANNER_RHAI_VERSION
    );
    assert_eq!(compiled_planner.script_bytes, project_planner_script());
    let expected_digest = digest(project_planner_script());
    assert_eq!(compiled_planner.script_sha256, expected_digest);
    let rendered_model = first
        .registry()
        .artifacts()
        .get("compiled/effective-model.json")
        .expect("compiled model artifact exists")
        .bytes
        .as_slice();
    let rendered_model = String::from_utf8_lossy(rendered_model);
    assert!(!rendered_model.contains(RHAI_PLANNER_CANARY));
    assert!(!rendered_model.contains("planners/request.rhai"));
    assert!(rendered_model.contains(&format!(
        "\"rhaiVersion\":\"{}\"",
        registry_server::change_request::CHANGE_REQUEST_PLANNER_RHAI_VERSION
    )));

    let mut revised_asset = asset.clone();
    revised_asset.bytes = project_planner_script()
        .iter()
        .copied()
        .chain(b"// reviewed revision\n".iter().copied())
        .collect();
    let revised = prepare_package_with_project_assets(request.clone(), vec![revised_asset])
        .expect("a revised valid planner packages");
    let changes =
        compiled_registry_change_set(first.registry(), revised.registry(), PRIOR_REVISION);
    assert_change(
        &changes,
        CompiledRegistryChangeClass::AccessOrDisclosureChange,
        CompiledRegistryChangeCode::ChangeRequestContractChanged,
    );
    assert_eq!(changes.changes.len(), 1);
    assert!(change_set_to_applicable_migration_plan(&changes)
        .expect("a request-contract-only change has no database migration")
        .statements
        .is_empty());

    let inspected = inspect_prepared(&first);
    let rederived = inspected.registry().entities()["request"]
        .change_request
        .as_ref()
        .and_then(|request| request.planner.as_ref())
        .expect("package inspection rederives the planner");
    assert_eq!(rederived.script_sha256, compiled_planner.script_sha256);
    assert_eq!(rederived.script_bytes, project_planner_script());

    let tamper_root = tempfile::Builder::new()
        .prefix("registry-planner-package-tamper-")
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    let tampered_package = tamper_root.path().join("package");
    first
        .publish_to_directory(&tampered_package, Vec::new())
        .unwrap();
    fs::write(
        tampered_package.join("source/project/planners/request.rhai"),
        b"fn plan(ctx) { #{ disposition: \"apply\", effects: [] } }\n",
    )
    .unwrap();
    assert_eq!(
        inspect_package_integrity(&tampered_package)
            .err()
            .expect("tampered package is refused"),
        PackageError::Integrity
    );

    let role_root = tempfile::Builder::new()
        .prefix("registry-planner-package-role-")
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    let role_swapped_package = role_root.path().join("package");
    first
        .publish_to_directory(&role_swapped_package, Vec::new())
        .unwrap();
    let manifest_path = role_swapped_package.join("package.json");
    let mut envelope: PackageEnvelope =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    envelope
        .signed
        .files
        .iter_mut()
        .find(|entry| entry.path == "source/project/planners/request.rhai")
        .unwrap()
        .role = PackageFileRole::SourceModulePlannerScript;
    envelope.signed.package_revision = derive_package_revision(&envelope.signed).unwrap();
    fs::write(&manifest_path, canonical(&envelope)).unwrap();
    assert_eq!(
        inspect_package_integrity(&role_swapped_package)
            .err()
            .expect("role-swapped package is refused"),
        PackageError::Derivation
    );

    assert_eq!(
        prepare_package_with_project_assets(request.clone(), Vec::new()).unwrap_err(),
        PackageError::Derivation
    );
    let mut extra = asset.clone();
    extra.path = "planners/extra.rhai".to_owned();
    assert_eq!(
        prepare_package_with_project_assets(request.clone(), vec![asset.clone(), extra])
            .unwrap_err(),
        PackageError::Derivation
    );
    for unsafe_path in ["../request.rhai", "/request.rhai"] {
        let mut unsafe_asset = asset.clone();
        unsafe_asset.path = unsafe_path.to_owned();
        assert!(prepare_package_with_project_assets(request.clone(), vec![unsafe_asset]).is_err());
    }
    let oversized = PackageSourceFile {
        path: asset.path,
        bytes: vec![b'x'; MAX_RHAI_PLANNER_SOURCE_BYTES as usize + 1],
    };
    assert_eq!(
        prepare_package_with_project_assets(request, vec![oversized]).unwrap_err(),
        PackageError::Derivation
    );
}

#[cfg(feature = "tooling")]
#[test]
fn module_rhai_planner_uses_module_origin_role_and_refuses_origin_swaps() {
    let request = module_planner_build_request();
    let prepared = prepare_package(request.clone()).expect("module planner packages");
    let entry = prepared
        .manifest()
        .files
        .iter()
        .find(|entry| entry.path == "source/modules/core/planners/request.rhai")
        .expect("module planner is in the signed closure");
    assert_eq!(entry.role, PackageFileRole::SourceModulePlannerScript);
    assert!(prepared.manifest().sources.project_assets.is_empty());
    assert_eq!(
        prepared.manifest().sources.modules[0].assets,
        ["planners/request.rhai"]
    );
    let compiled = prepared.registry().entities()["request"]
        .change_request
        .as_ref()
        .and_then(|request| request.planner.as_ref())
        .expect("compiled module planner exists");
    assert_eq!(compiled.source_module.as_deref(), Some("core"));
    assert_eq!(compiled.script_bytes, project_planner_script());
    let inspected = inspect_prepared(&prepared);
    assert_eq!(
        inspected.registry().entities()["request"]
            .change_request
            .as_ref()
            .and_then(|request| request.planner.as_ref())
            .unwrap()
            .script_sha256,
        compiled.script_sha256
    );

    let script = request.modules[0].assets[0].clone();
    let mut swapped = request;
    swapped.modules[0].assets.clear();
    assert_eq!(
        prepare_package_with_project_assets(swapped, vec![script]).unwrap_err(),
        PackageError::Derivation
    );
}

#[test]
fn geojson_binding_changes_are_classified_as_disclosure_even_for_get_only_profiles() {
    for (previous_binding, candidate_binding) in [
        (None, Some("location")),
        (Some("location"), None),
        (Some("location"), Some("alternate")),
    ] {
        let previous = compile_source(&geojson_source(1, previous_binding));
        let candidate = compile_source(&geojson_source(2, candidate_binding));
        let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
        assert_change(
            &change_set,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            CompiledRegistryChangeCode::EntityGeoJsonChanged,
        );
        assert_eq!(change_set.changes.len(), 1);
        let plan = change_set_to_applicable_migration_plan(&change_set)
            .expect("metadata-only GeoJSON changes create an applicable plan");
        assert!(plan.statements.is_empty());
        assert!(plan.reviewed_descriptors.is_empty());
        assert_eq!(previous.ddl().script(), candidate.ddl().script());
    }
}

#[cfg(feature = "tooling")]
#[test]
fn geojson_only_successor_uses_existing_metadata_review_without_dummy_sql() {
    let previous = compile_source(&geojson_source(1, None));
    let source = geojson_source(2, Some("location"));
    let candidate = compile_source(&source);
    let migrations = vec![metadata_only_source_between(&previous, &candidate)];
    let package = prepare_package(build_request(
        2,
        Some(PRIOR_REVISION),
        source.project_bytes,
        source.module_bytes,
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(previous),
            prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
            migrations,
        },
    ))
    .expect("GeoJSON representation can be reviewed without spatial storage SQL");
    assert!(package.manifest().migration_plan.statements.is_empty());
}

#[test]
fn legacy_nonspatial_successor_baseline_roundtrips_without_new_keys() {
    let compiled = compile_variant(Variant::Base, 1);
    let baseline = registry_server::package::CompiledRegistryMigrationBaseline::from_compiled(
        PRIOR_REVISION,
        &compiled,
    );
    let value = serde_json::to_value(&baseline).expect("baseline serializes");
    let bytes = canonicalize_json(&value).expect("baseline canonicalizes");
    let parsed: registry_server::package::CompiledRegistryMigrationBaseline =
        serde_json::from_slice(&bytes).expect("baseline without optional spatial keys loads");
    let encoded = canonicalize_json(&serde_json::to_value(parsed).unwrap()).unwrap();
    assert_eq!(bytes, encoded);
    let text = std::str::from_utf8(&bytes).unwrap();
    for key in ["\"geojson\"", "\"spatial\"", "\"spatialQueries\""] {
        assert!(
            !text.contains(key),
            "absent capability must not change signed baseline bytes"
        );
    }
}

#[cfg(feature = "tooling")]
#[test]
fn spatial_span_numbers_survive_canonical_package_reload_and_successor_rederive() {
    let source_with_span = |sequence, span: serde_json::Value, add_field| {
        let source = spatial_source(sequence, "location", true);
        let mut module: serde_json::Value = serde_json::from_slice(&source.module_bytes).unwrap();
        let entity = &mut module["entities"][0];
        let bbox = &mut entity["accessProfiles"][0]["spatialQueries"]["bbox"];
        bbox["maximumLongitudeSpanDegrees"] = span.clone();
        bbox["maximumLatitudeSpanDegrees"] = span;
        if add_field {
            entity["fields"].as_array_mut().unwrap().push(json!({
                "id": "color", "type": "string", "maxLength": 16,
                "classification": "internal"
            }));
        }
        let module_bytes = serde_json::to_vec(&module).unwrap();
        let module = parse_module_yaml(&module_bytes).unwrap();
        SourceFixture {
            project_bytes: project_bytes(sequence, &module_digest(&module)),
            module_bytes,
        }
    };
    let previous = compile_source(&source_with_span(1, json!(1.0), false));
    let equivalent = compile_source(&source_with_span(1, json!(1), false));
    assert!(
        compiled_registry_change_set(&previous, &equivalent, PRIOR_REVISION)
            .changes
            .is_empty()
    );

    let baseline = registry_server::package::CompiledRegistryMigrationBaseline::from_compiled(
        PRIOR_REVISION,
        &previous,
    );
    let reloaded: registry_server::package::CompiledRegistryMigrationBaseline =
        serde_json::from_slice(&canonical(&baseline)).unwrap();
    assert_eq!(
        baseline, reloaded,
        "signed numeric normalization preserves equality"
    );

    let source = source_with_span(2, json!(1.0), true);
    let package = prepare_package(build_request(
        2,
        Some(PRIOR_REVISION),
        source.project_bytes,
        source.module_bytes,
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(previous),
        },
    ))
    .expect("a spatial successor does not invent an access change from 1.0 versus 1");
    let inspected = inspect_prepared(&package);
    assert_eq!(inspected.migration_summary().change_count(), 1);
}

#[cfg(feature = "tooling")]
#[test]
fn reviewed_bbox_enablement_compiles_storage_without_author_written_sql() {
    let previous = compile_source(&spatial_source(1, "location", false));
    let source = spatial_source(2, "location", true);
    let candidate = compile_source(&source);
    let package = prepare_spatial_successor(previous, source, &candidate);
    let statements = &package.manifest().migration_plan.statements;
    assert_eq!(statements.len(), 4);
    assert!(statements[0]
        .sql
        .contains("CREATE OR REPLACE FUNCTION registry_context.spatial_bbox_geometry"));
    assert!(statements[1].sql.contains("ADD COLUMN"));
    assert!(statements[1].sql.contains("GENERATED ALWAYS AS"));
    assert!(statements[1]
        .sql
        .contains("registry_spatial_ext.geometry(Point,4326)"));
    assert!(statements[2].sql.contains("USING gist"));
    assert_eq!(statements[3].id, "entity.asset.spatial-candidates-view");
    assert!(statements[3]
        .sql
        .starts_with("CREATE VIEW registry_context."));
    assert!(statements[3]
        .sql
        .contains("security_invoker=false, security_barrier=true"));
    assert!(!statements
        .iter()
        .any(|statement| statement.sql.contains("CREATE EXTENSION")));
}

#[cfg(feature = "tooling")]
#[test]
fn reviewed_bbox_removal_drops_candidates_and_policy_before_internal_projection() {
    let previous = compile_source(&spatial_source(1, "location", true));
    let logical_point_column = previous.entities()["asset"].fields["location"]
        .physical_name
        .clone();
    let source = spatial_source(2, "location", false);
    let candidate = compile_source(&source);
    let package = prepare_spatial_successor(previous, source, &candidate);
    let statements = &package.manifest().migration_plan.statements;
    assert_eq!(statements.len(), 5);
    assert_eq!(
        statements[0].id,
        "entity.asset.spatial-candidates-view.drop"
    );
    assert!(statements[0]
        .sql
        .starts_with("DROP VIEW IF EXISTS registry_context."));
    assert!(statements[1].sql.starts_with("DROP POLICY"));
    assert!(statements[2].sql.starts_with("DROP INDEX"));
    assert!(statements[3].sql.contains("DROP COLUMN"));
    assert!(statements[4].sql.starts_with("DROP FUNCTION"));
    assert!(!statements
        .iter()
        .any(|statement| statement.sql.contains(&logical_point_column)));
    assert!(!statements
        .iter()
        .any(|statement| statement.sql.contains("DROP EXTENSION")
            || statement.sql.contains("CASCADE")));
}

#[cfg(feature = "tooling")]
#[test]
fn changing_primary_bbox_point_replaces_projection_without_replacing_source_fields() {
    let previous = compile_source(&spatial_source(1, "location", true));
    let source = spatial_source(2, "alternate", true);
    let candidate = compile_source(&source);
    let package = prepare_spatial_successor(previous, source, &candidate);
    let statements = &package.manifest().migration_plan.statements;
    assert_eq!(statements.len(), 7);
    assert_eq!(
        statements[0].id,
        "entity.asset.spatial-candidates-view.drop"
    );
    assert!(statements[1].sql.starts_with("DROP POLICY"));
    assert!(statements[2].sql.starts_with("DROP INDEX"));
    assert!(statements[3].sql.contains("DROP COLUMN"));
    assert!(statements[4].sql.contains("ADD COLUMN"));
    assert!(statements[5].sql.contains("CREATE INDEX"));
    assert_eq!(statements[6].id, "entity.asset.spatial-candidates-view");
    assert!(!statements
        .iter()
        .any(|statement| statement.sql.contains("DROP FUNCTION")));
    for field in ["location", "alternate"] {
        assert!(candidate.entities()["asset"].fields.contains_key(field));
    }
}

#[cfg(feature = "tooling")]
#[test]
fn changing_bbox_grant_replaces_candidate_view_without_rewriting_point_storage() {
    let previous = compile_source(&spatial_source(1, "location", true));
    let source = spatial_source(2, "location", true);
    let mut module: serde_json::Value = serde_json::from_slice(&source.module_bytes).unwrap();
    module["entities"][0]["accessProfiles"][0]["spatialQueries"]["bbox"]
        ["maximumLongitudeSpanDegrees"] = json!(0.25);
    let module_bytes = serde_json::to_vec(&module).unwrap();
    let parsed_module = parse_module_yaml(&module_bytes).unwrap();
    let source = SourceFixture {
        project_bytes: project_bytes(2, &module_digest(&parsed_module)),
        module_bytes,
    };
    let candidate = compile_source(&source);
    let package = prepare_spatial_successor(previous, source, &candidate);
    let statements = &package.manifest().migration_plan.statements;
    assert_eq!(statements.len(), 2);
    assert_eq!(
        statements[0].id,
        "entity.asset.spatial-candidates-view.drop"
    );
    assert_eq!(statements[1].id, "entity.asset.spatial-candidates-view");
    let candidate_definition = candidate
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.asset.spatial-candidates-view")
        .unwrap();
    assert_eq!(statements[1], *candidate_definition);
}

#[cfg(feature = "tooling")]
#[test]
fn reviewed_source_view_refresh_preserves_candidate_drop_and_recreation() {
    let previous = compile_source(&spatial_source(1, "location", true));
    let source = spatial_source(2, "location", true);
    let mut module: serde_json::Value = serde_json::from_slice(&source.module_bytes).unwrap();
    module["entities"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": "color", "type": "string", "maxLength": 16,
            "classification": "internal"
        }));
    module["entities"][0]["accessProfiles"][0]["allowCount"] = json!(true);
    let module_bytes = serde_json::to_vec(&module).unwrap();
    let parsed_module = parse_module_yaml(&module_bytes).unwrap();
    let source = SourceFixture {
        project_bytes: project_bytes(2, &module_digest(&parsed_module)),
        module_bytes,
    };
    let candidate = compile_source(&source);
    let view_id = "entity.asset.spatial-candidates-view";
    assert_eq!(
        previous.ddl().statements.iter().find(|s| s.id == view_id),
        candidate.ddl().statements.iter().find(|s| s.id == view_id),
        "the view lifecycle must also work when its predicate did not change"
    );
    let package = prepare_spatial_successor(previous, source, &candidate);
    let statements = &package.manifest().migration_plan.statements;
    assert_eq!(
        statements[0].id,
        "entity.asset.spatial-candidates-view.drop"
    );
    assert_eq!(statements[1].id, "entity.asset.field.color.column");
    assert_eq!(statements.iter().filter(|s| s.id == view_id).count(), 1);
    assert!(statements
        .iter()
        .any(|s| s.id == "entity.asset.source-view"));
    assert!(!statements.iter().any(|s| s.sql.contains("DROP COLUMN")
        || s.sql.contains("geometry(Point,4326)")
        || s.sql.contains("USING gist")));
}

#[cfg(feature = "tooling")]
fn prepare_spatial_successor(
    previous: CompiledRegistry,
    source: SourceFixture,
    candidate: &CompiledRegistry,
) -> PreparedPackage {
    let migrations = vec![metadata_only_source_between(&previous, candidate)];
    prepare_package(build_request(
        2,
        Some(PRIOR_REVISION),
        source.project_bytes,
        source.module_bytes,
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(previous),
            prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
            migrations,
        },
    ))
    .expect("reviewed spatial change derives its exact storage plan")
}

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
fn data_destructive_and_unsupported_changes_cannot_create_applicable_plans() {
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
            Variant::TemporalChanged,
            CompiledRegistryChangeClass::DestructiveOrIrreversible,
            CompiledRegistryChangeCode::EntityTemporalChanged,
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
fn metadata_only_access_or_disclosure_changes_create_empty_applicable_plans() {
    for (previous_variant, candidate_variant, code) in [
        (
            Variant::Base,
            Variant::RouteChanged,
            CompiledRegistryChangeCode::EntityRouteChanged,
        ),
        (
            Variant::Base,
            Variant::EntityClassificationChanged,
            CompiledRegistryChangeCode::EntityClassificationChanged,
        ),
        (
            Variant::Base,
            Variant::ClassificationChanged,
            CompiledRegistryChangeCode::FieldClassificationChanged,
        ),
        (
            Variant::Base,
            Variant::AuthorizationChanged,
            CompiledRegistryChangeCode::AccessProfileChanged,
        ),
        (
            Variant::Base,
            Variant::MutationModeChanged,
            CompiledRegistryChangeCode::EntityMutationModeChanged,
        ),
        (
            Variant::TemporalRoleBase,
            Variant::TemporalRoleChanged,
            CompiledRegistryChangeCode::FieldTemporalRoleChanged,
        ),
    ] {
        let previous = compile_variant(previous_variant, 1);
        let candidate = compile_variant(candidate_variant, 2);
        let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
        assert_change(
            &change_set,
            CompiledRegistryChangeClass::AccessOrDisclosureChange,
            code,
        );
        let plan = change_set_to_applicable_migration_plan(&change_set)
            .expect("metadata-only policy changes create an applicable plan");
        assert!(plan.statements.is_empty());
        assert!(plan.reviewed_descriptors.is_empty());
        assert!(plan
            .changes
            .iter()
            .all(|change| change.class == CompiledRegistryChangeClass::AccessOrDisclosureChange));
    }
}

#[test]
fn complete_extension_surface_modules_are_order_independent() {
    let field_module = parse_module_yaml(br#"{"id":"field-extension","version":"1","extendEntities":[{"entity":"asset","fields":[{"id":"status","type":"string","maxLength":16,"classification":"internal"}],"constraints":[{"kind":"unique","id":"status-unique","fields":["status"]}],"indexes":[{"id":"status-idx","fields":["status"]}]}]}"#)
        .expect("field extension parses");
    let event_module = parse_module_yaml(br#"{"id":"event-extension","version":"1","extendEntities":[{"entity":"asset","accessProfiles":[{"id":"auditor","principalClaim":"principal","operations":["get","list"],"readableFields":["code","status"],"writableFields":[]}],"events":[{"id":"asset-created","trigger":"created","projection":["code","status"],"webhook":{"destinationId":"package-change-events"}}]}],"entities":[{"id":"site","primaryDataset":"neutral-registry","route":"sites","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}]}]}"#)
        .expect("event extension parses");
    let project_bytes = format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"environment":"local","instanceId":"{INSTANCE}","sequence":2,"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}}},"publicService":{{"id":"neutral-registry-service","title":"Neutral Registry Catalog"}},"datasets":[{{"id":"neutral-registry","title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"neutral-registry-data-service","title":"Neutral Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["neutral-registry"]}}]}},"entities":[{{"id":"asset","primaryDataset":"neutral-registry","route":"assets","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":8,"classification":"internal"}}]}}],"accessProfiles":[{{"id":"reader","default":true,"principalClaim":"principal","grants":[{{"entity":"asset","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}}]}}],"modules":[{{"id":"field-extension","version":"1","digest":"{}"}},{{"id":"event-extension","version":"1","digest":"{}"}}]}}"#,
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
fn metadata_only_policy_surface_can_apply_automatically_and_be_reviewed_without_dummy_sql() {
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
    let automatic = change_set_to_applicable_migration_plan(&change_set)
        .expect("metadata-only policy surface creates an automatic applicable plan");
    assert!(automatic.statements.is_empty());
    assert!(automatic.reviewed_descriptors.is_empty());

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
        // The added required field contributes its nullable column and the
        // deferred NOT NULL statement on top of the replacement views.
        "generatedStatementCount": 5,
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

fn compile_source(source: &SourceFixture) -> CompiledRegistry {
    let module = parse_module_yaml(&source.module_bytes).expect("fixture module parses");
    let project = parse_project_yaml(&source.project_bytes).expect("fixture project parses");
    compile_project(&project, &[module], CompileProfile::Production).expect("fixture compiles")
}

fn geojson_source(sequence: u64, binding: Option<&str>) -> SourceFixture {
    let mut module: serde_json::Value =
        serde_json::from_slice(&module_bytes(Variant::Base)).unwrap();
    let entity = &mut module["entities"][0];
    let fields = entity["fields"].as_array_mut().unwrap();
    for id in ["location", "alternate"] {
        fields.push(serde_json::json!({
            "id": id, "type": "crs84-point", "precision": 9, "classification": "internal"
        }));
    }
    entity["accessProfiles"][0]["operations"] = serde_json::json!(["get"]);
    entity["accessProfiles"][0]["writableFields"] = serde_json::json!([]);
    entity["accessProfiles"][0]["readableFields"] =
        serde_json::json!(["code", "location", "alternate"]);
    if let Some(binding) = binding {
        entity["geojson"] = serde_json::json!({"geometryField": binding});
    }
    let module_bytes = serde_json::to_vec(&module).unwrap();
    let module = parse_module_yaml(&module_bytes).expect("Point module parses");
    SourceFixture {
        project_bytes: project_bytes(sequence, &module_digest(&module)),
        module_bytes,
    }
}

#[cfg(feature = "tooling")]
fn spatial_source(sequence: u64, binding: &str, bbox: bool) -> SourceFixture {
    let source = geojson_source(sequence, Some(binding));
    let mut module: serde_json::Value = serde_json::from_slice(&source.module_bytes).unwrap();
    let profile = &mut module["entities"][0]["accessProfiles"][0];
    profile["operations"] = json!(["get", "list"]);
    if bbox {
        profile["spatialQueries"] = json!({"bbox": {
            "maximumLongitudeSpanDegrees": 0.5,
            "maximumLatitudeSpanDegrees": 0.25
        }});
    }
    let module_bytes = serde_json::to_vec(&module).unwrap();
    let module = parse_module_yaml(&module_bytes).unwrap();
    SourceFixture {
        project_bytes: project_bytes(sequence, &module_digest(&module)),
        module_bytes,
    }
}

fn project_bytes(sequence: u64, module_digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"environment":"local","instanceId":"{INSTANCE}","sequence":{sequence},"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}}},"publicService":{{"id":"neutral-registry-service","title":"Neutral Registry Catalog"}},"datasets":[{{"id":"neutral-registry","title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"neutral-registry-data-service","title":"Neutral Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["neutral-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    )
    .into_bytes()
}

fn derived_source_for_sql(sequence: u64, sql: &[u8]) -> DerivedSourceFixture {
    let module_bytes = br#"{"id":"core","version":"1","entities":[{"id":"asset","primaryDataset":"neutral-registry","route":"assets","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"derived":[{"id":"summary","sql":"sql/summary.sql","key":"id","fields":[{"id":"summary","type":"string","maxLength":16,"classification":"internal"}]}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code","summary"]}]}]}"#.to_vec();
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
        r#"{{"id":"asset","primaryDataset":"neutral-registry",{route},"mutationMode":"{mutation_mode}","fields":[{fields}]{constraints}{indexes},"accessProfiles":[{{{access}}}]{temporal}}}"#
    )
}

fn site_entity() -> &'static str {
    r#"{"id":"site","primaryDataset":"neutral-registry","route":"sites","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}]}"#
}

fn location_entity() -> &'static str {
    r#"{"id":"location","primaryDataset":"neutral-registry","route":"locations","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}]}"#
}

fn placement_entity() -> &'static str {
    r#"{"id":"placement","primaryDataset":"neutral-registry","route":"placements","mutationMode":"create_only","fields":[{"id":"asset","type":"reference","target":"asset","required":true,"classification":"internal"},{"id":"site","type":"reference","target":"site","required":true,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["asset","site"],"writableFields":["asset","site"]}]}"#
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
fn project_planner_build_request() -> PackageBuildRequest {
    let project = format!(
        r#"{{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{{"id":"planner-package","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},
          "package":{{"environment":"local","instanceId":"{INSTANCE}","sequence":1,"sourceRevision":"{SOURCE_REVISION}"}},
          "entities":[{{
            "id":"target","primaryDataset":"planner-package","route":"targets","mutationMode":"mutable","changeControl":{{"requiredFor":["patch"]}},
            "fields":[{{"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}}]
          }},{{
            "id":"request","primaryDataset":"planner-package","route":"requests","mutationMode":"mutable",
            "fields":[
              {{"id":"target","type":"reference","target":"target","required":true,"classification":"internal"}},
              {{"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}}
            ],
            "changeRequest":{{
              "planner":{{"kind":"rhai","script":"planners/request.rhai","abi":"registry.change-request-plan/v1","requestFields":["target","label"],"writes":[{{"target":{{"fromField":"target"}},"operation":"patch","fields":["label"]}}]}},
              "review":{{"stages":[{{"id":"review","approvals":1}}]}},
              "application":{{"mode":"planner","allowedDispositions":["apply"]}}
            }}
          }}],
          "accessProfiles":[{{
            "id":"operator","default":true,"principalClaim":"principal","grants":[
              {{"entity":"target","operations":["get","list"],"readableFields":["label"]}},
              {{"entity":"request","operations":["create","patch","get","list","submit_request","revise_request","cancel_request","approve_request","reject_request","request_revision","apply_request"],"readableFields":["target","label"],"writableFields":["target","label"],
                "reviewStages":[{{"stage":"review","targets":[{{"entity":"target","readableFields":["label"]}}]}}],
                "applyTargets":[{{"entity":"target"}}]
              }}
            ]
          }}]
        }}"#
    )
    .into_bytes();
    PackageBuildRequest {
        environment: "local".to_owned(),
        instance_id: INSTANCE.to_owned(),
        database_id: DATABASE.to_owned(),
        sequence: 1,
        prior_revision: None,
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint:
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project,
        },
        modules: Vec::new(),
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: b"apiVersion: registry.registrystack.org/server-journeys/v1\njourneys: []\n"
                .to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    }
}

#[cfg(feature = "tooling")]
fn module_planner_build_request() -> PackageBuildRequest {
    let module_bytes = br#"{
      "id":"core","version":"1","entities":[{
        "id":"target","primaryDataset":"planner-package","route":"targets","mutationMode":"mutable","changeControl":{"requiredFor":["patch"]},
        "fields":[{"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}],
        "accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["label"]}]
      },{
        "id":"request","primaryDataset":"planner-package","route":"requests","mutationMode":"mutable",
        "fields":[
          {"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
          {"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}
        ],
        "changeRequest":{
          "planner":{"kind":"rhai","script":"planners/request.rhai","abi":"registry.change-request-plan/v1","requestFields":["target","label"],"writes":[{"target":{"fromField":"target"},"operation":"patch","fields":["label"]}]},
          "review":{"stages":[{"id":"review","approvals":1}]},
          "application":{"mode":"planner","allowedDispositions":["apply"]}
        },
        "accessProfiles":[{"id":"operator","principalClaim":"principal","operations":["create","patch","get","list","submit_request","revise_request","cancel_request","approve_request","reject_request","request_revision","apply_request"],"readableFields":["target","label"],"writableFields":["target","label"],
          "reviewStages":[{"stage":"review","targets":[{"entity":"target","readableFields":["label"]}]}],
          "applyTargets":[{"entity":"target"}]
        }]
      }]
    }"#
    .to_vec();
    let module = parse_module_yaml(&module_bytes).expect("planner module parses");
    let module_asset = ModuleAssetSource {
        module: Some("core".to_owned()),
        path: "planners/request.rhai".to_owned(),
        bytes: project_planner_script().to_vec(),
    };
    let module_digest = module_digest_with_assets(&module, &[module_asset]);
    let project = format!(
        r#"{{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{{"id":"planner-package","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},
          "package":{{"environment":"local","instanceId":"{INSTANCE}","sequence":1,"sourceRevision":"{SOURCE_REVISION}"}},
          "modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]
        }}"#
    )
    .into_bytes();
    PackageBuildRequest {
        environment: "local".to_owned(),
        instance_id: INSTANCE.to_owned(),
        database_id: DATABASE.to_owned(),
        sequence: 1,
        prior_revision: None,
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint:
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project,
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.yaml".to_owned(),
            bytes: module_bytes,
            assets: vec![PackageSourceFile {
                path: "planners/request.rhai".to_owned(),
                bytes: project_planner_script().to_vec(),
            }],
        }],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: b"apiVersion: registry.registrystack.org/server-journeys/v1\njourneys: []\n"
                .to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    }
}

#[cfg(feature = "tooling")]
fn project_planner_script() -> &'static [u8] {
    br#"// rhai-package-source-canary
fn plan(ctx) {
    #{ disposition: "apply", effects: [] }
}
"#
}

#[cfg(feature = "tooling")]
fn metadata_only_source(candidate: &CompiledRegistry) -> ReviewedMigrationSource {
    let previous = compile_variant(Variant::MetadataOnlyBase, 1);
    metadata_only_source_between(&previous, candidate)
}

#[cfg(feature = "tooling")]
fn metadata_only_source_between(
    previous: &CompiledRegistry,
    candidate: &CompiledRegistry,
) -> ReviewedMigrationSource {
    let change_set = compiled_registry_change_set(previous, candidate, PRIOR_REVISION);
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

#[test]
fn a_changed_registry_version_is_named_and_explained_in_the_change_set() {
    let previous = compile_variant(Variant::Base, 1);
    let mut source = source_for_variant(Variant::Base, 2);
    source.project_bytes = String::from_utf8(source.project_bytes)
        .expect("the fixture project is UTF-8")
        .replace(
            r#""neutral-registry","version":"1""#,
            r#""neutral-registry","version":"2""#,
        )
        .into_bytes();
    let candidate = compile_source(&source);

    let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
    assert_change(
        &change_set,
        CompiledRegistryChangeClass::Unsupported,
        CompiledRegistryChangeCode::RegistryVersionChanged,
    );
    let explanation = CompiledRegistryChangeCode::RegistryVersionChanged
        .explanation()
        .expect("the version refusal explains why it cannot migrate");
    assert!(
        explanation.contains("registry.version"),
        "the explanation names the key: {explanation}"
    );
    assert!(
        explanation.contains("bound to the database"),
        "the explanation says the value is bound for the database lifetime: {explanation}"
    );
    assert!(change_set_to_applicable_migration_plan(&change_set).is_err());

    let unchanged = compiled_registry_change_set(
        &previous,
        &compile_variant(Variant::Base, 2),
        PRIOR_REVISION,
    );
    assert!(
        !unchanged
            .changes
            .iter()
            .any(|change| change.code == CompiledRegistryChangeCode::RegistryVersionChanged),
        "an unchanged registry version reports no version change"
    );
    assert_eq!(
        CompiledRegistryChangeCode::EntityAdded.explanation(),
        None,
        "a code that says everything in its name carries no extra sentence"
    );
}

#[cfg(feature = "tooling")]
#[test]
fn disagreeing_environment_identity_keys_refuse_the_package_and_name_both_values() {
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
        .prefix("registry-package-environment-keys-")
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

    let matching = registry_server::package::PackageInspectionContext {
        environment: "local",
        instance_id: INSTANCE,
        database_id: DATABASE,
        database_initialization_environment: "local",
        compiler_source_revision: SOURCE_REVISION,
        trust_anchor: None,
        expected_package_revision: prepared.package_revision(),
        expected_sequence: 1,
    };
    registry_server::package::inspect_package_with_context(&package, &matching)
        .expect("identical environment keys bind the package");

    let disagreeing = registry_server::package::PackageInspectionContext {
        database_initialization_environment: "production",
        ..matching
    };
    let error = registry_server::package::inspect_package_with_context(&package, &disagreeing)
        .err()
        .expect("disagreeing environment keys cannot bind any package");
    assert_eq!(error, registry_server::package::PackageError::Binding);

    assert_eq!(
        registry_server::package::environment_identity_conflict("local", "local"),
        None,
        "identical values carry no conflict to report"
    );
    assert_eq!(
        registry_server::package::environment_identity_conflict("local", "production").as_deref(),
        Some(
            "`identity.environment` and `identity.databaseInitializationEnvironment` must be identical: `identity.environment` is `local`, `identity.databaseInitializationEnvironment` is `production`"
        )
    );
    assert_eq!(
        registry_server::package::ENVIRONMENT_IDENTITY_KEYS,
        [
            "identity.environment",
            "identity.databaseInitializationEnvironment"
        ]
    );
}
