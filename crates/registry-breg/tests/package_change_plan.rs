#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "runtime")]

#[cfg(feature = "tooling")]
use std::fs;

use registry_breg::compiler::{
    compile_project, compile_project_with_assets, module_digest, module_digest_with_assets,
    CompileProfile,
};
use registry_breg::contract::{
    parse_module_yaml, parse_project_json, parse_project_yaml, ModuleAssetSource,
};
#[cfg(feature = "tooling")]
use registry_breg::migration_plan::{
    ArtifactDigestBinding, ChunkCursorProtocol, MigrationRehearsalReceipt, RehearsalFixture,
    RehearsalRowAssertion, ReviewedChangeCover, ReviewedMigrationAssertionDescriptor,
    ReviewedMigrationDescriptor, ReviewedMigrationFile, ReviewedMigrationObject,
    ReviewedMigrationObjectKind, ReviewedMigrationRecovery, ReviewedMigrationSource,
    ReviewedMigrationStepDescriptor,
};
use registry_breg::package::{
    change_set_to_applicable_migration_plan, compiled_registry_change_set,
    CompiledRegistryChangeClass, CompiledRegistryChangeCode, PackageBuildRequest,
    PackageMigrationPlanInput, PackageModuleSource, PackageSourceFile,
};
#[cfg(feature = "tooling")]
use registry_breg::package::{
    compiled_registry_change_set_from_baseline, inspect_package_integrity,
    load_predecessor_package, prepare_package, prepare_package_with_project_assets,
    PackageEnvelope, PackageError, PackageFileRole, PackageLoadContext, PreparedPackage,
    MAX_RHAI_PLANNER_SOURCE_BYTES,
};
use registry_breg::CompiledRegistry;
use registry_platform_canonical_json::canonicalize_json;
#[cfg(feature = "tooling")]
use registry_platform_config::{
    write_sum_file, PackageLimits as SharedPackageLimits, REVISION_FILE, SUM_FILE,
};
#[cfg(feature = "tooling")]
use serde::Serialize;
#[cfg(feature = "tooling")]
use serde_json::json;
#[cfg(feature = "tooling")]
use sha2::{Digest, Sha256};

const INSTANCE: &str = "instance-under-test";
const DATABASE: &str = "database-under-test";
const SOURCE_REVISION: &str = "compiler-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: asset-list
    steps:
      - id: list-assets
        entity: asset
        accessProfile: reader
        claims: {principal: package-reader}
        request: {type: list}
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
#[cfg(feature = "tooling")]
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
    assert_eq!(
        first.package_digest().unwrap(),
        second.package_digest().unwrap()
    );
    assert_eq!(canonical(&first.envelope()), canonical(&second.envelope()));
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
    assert!(!String::from_utf8_lossy(&canonical(&first.envelope())).contains(RHAI_PLANNER_CANARY));

    let compiled_planner = first.registry().entities()["request"]
        .change_request
        .as_ref()
        .and_then(|request| request.planner.as_ref())
        .expect("compiled planner exists");
    assert_eq!(compiled_planner.source_module, None);
    assert_eq!(compiled_planner.script_path, "planners/request.rhai");
    assert_eq!(
        compiled_planner.rhai_version,
        registry_breg::change_request::CHANGE_REQUEST_PLANNER_RHAI_VERSION
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
        registry_breg::change_request::CHANGE_REQUEST_PLANNER_RHAI_VERSION
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
    let policy_plan = change_set_to_applicable_migration_plan(&changes)
        .expect("a request-contract-only change has a compiler-owned policy migration");
    assert!(!policy_plan.statements.is_empty());
    assert!(policy_plan
        .statements
        .iter()
        .all(|statement| statement.sql.starts_with("DROP POLICY IF EXISTS ")));
    assert!(policy_plan
        .statements
        .iter()
        .any(|statement| statement.sql.starts_with("DROP POLICY ")));

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
    first.publish_to_directory(&tampered_package).unwrap();
    fs::write(
        tampered_package.join("source/project/planners/request.rhai"),
        b"fn plan(ctx) { #{ disposition: \"apply\", effects: [] } }\n",
    )
    .unwrap();
    refresh_shared_package_envelope(&tampered_package);
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
    first.publish_to_directory(&role_swapped_package).unwrap();
    let manifest_path = role_swapped_package.join("package.json");
    let mut envelope: PackageEnvelope =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    envelope
        .manifest
        .files
        .iter_mut()
        .find(|entry| entry.path == "source/project/planners/request.rhai")
        .unwrap()
        .role = PackageFileRole::SourceModulePlannerScript;
    fs::write(&manifest_path, canonical(&envelope)).unwrap();
    refresh_shared_package_envelope(&role_swapped_package);
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

#[cfg(feature = "tooling")]
#[test]
fn rhai_planner_package_is_a_readable_predecessor() {
    let project = prepare_package_with_project_assets(
        project_planner_build_request(),
        vec![PackageSourceFile {
            path: "planners/request.rhai".to_owned(),
            bytes: project_planner_script().to_vec(),
        }],
    )
    .expect("declared project planner packages");
    let module = prepare_package(module_planner_build_request()).expect("module planner packages");

    for (prepared, source_module) in [(project, None), (module, Some("core"))] {
        let root = tempfile::Builder::new()
            .prefix("registry-planner-package-predecessor-")
            .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .unwrap();
        let package = root.path().join("package");
        prepared.publish_to_directory(&package).unwrap();
        let compiled = prepared.registry().entities()["request"]
            .change_request
            .as_ref()
            .expect("compiled change request exists");
        let compiled_planner = compiled.planner.as_ref().expect("compiled planner exists");

        let predecessor = load_predecessor_package(
            &package,
            &PackageLoadContext {
                database_initialization_environment: "local",
            },
        )
        .expect("a package with a change-request planner is accepted as a predecessor");
        let baseline = predecessor.migration_baseline().entities["request"]
            .change_request
            .as_ref()
            .expect("the predecessor baseline carries the change request");
        assert_eq!(baseline.contract_fingerprint, compiled.contract_fingerprint);
        let baseline_planner = baseline
            .planner
            .as_ref()
            .expect("the predecessor baseline carries the planner");
        assert_eq!(baseline_planner.source_module.as_deref(), source_module);
        assert_eq!(
            baseline_planner.script_sha256,
            compiled_planner.script_sha256
        );
        assert_eq!(baseline_planner.writes, compiled_planner.writes);
    }
}

#[cfg(feature = "tooling")]
#[test]
fn rhai_planner_predecessor_without_a_declared_origin_is_refused() {
    let prepared =
        prepare_package(module_planner_build_request()).expect("module planner packages");
    let context = PackageLoadContext {
        database_initialization_environment: "local",
    };
    let effective_model = "effective-model.json";

    // The republished envelope and manifest are themselves accepted, so the
    // refusal below belongs to the missing origin alone.
    for (remove_origin, expected) in [(false, None), (true, Some(PackageError::Derivation))] {
        let root = tempfile::Builder::new()
            .prefix("registry-planner-package-origin-")
            .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .unwrap();
        let package = root.path().join("package");
        prepared.publish_to_directory(&package).unwrap();

        let model_path = package.join(effective_model);
        let mut model: serde_json::Value =
            serde_json::from_slice(&fs::read(&model_path).unwrap()).unwrap();
        let planner = model["entities"]["request"]["changeRequest"]["planner"]
            .as_object_mut()
            .expect("the packaged effective model carries the planner");
        assert_eq!(
            planner["declaringOrigin"],
            json!({"kind": "module", "id": "core"})
        );
        if remove_origin {
            planner.remove("declaringOrigin");
        }
        let bytes = canonicalize_json(&model).unwrap();
        fs::write(&model_path, &bytes).unwrap();

        let manifest_path = package.join("package.json");
        let mut envelope: PackageEnvelope =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        let entry = envelope
            .manifest
            .files
            .iter_mut()
            .find(|entry| entry.path == effective_model)
            .unwrap();
        entry.size = bytes.len() as u64;
        entry.sha256 = digest(&bytes);
        fs::write(&manifest_path, canonical(&envelope)).unwrap();
        refresh_shared_package_envelope(&package);

        assert_eq!(
            load_predecessor_package(&package, &context).err(),
            expected,
            "declaringOrigin removed: {remove_origin}"
        );
    }
}

#[cfg(feature = "tooling")]
#[test]
fn rhai_planner_predecessor_plans_an_additive_successor() {
    let planner_asset = || PackageSourceFile {
        path: "planners/request.rhai".to_owned(),
        bytes: project_planner_script().to_vec(),
    };
    let first =
        prepare_package_with_project_assets(project_planner_build_request(), vec![planner_asset()])
            .expect("declared project planner packages");
    let root = tempfile::Builder::new()
        .prefix("registry-planner-package-successor-")
        .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
        .unwrap();
    let package = root.path().join("package");
    first.publish_to_directory(&package).unwrap();
    let context = PackageLoadContext {
        database_initialization_environment: "local",
    };
    let predecessor = load_predecessor_package(&package, &context)
        .expect("a package with a change-request planner is accepted as a predecessor");

    let mut request = project_planner_build_request();
    let entities = r#""entities":["#;
    let project = String::from_utf8(request.project.bytes).unwrap();
    assert!(project.contains(entities));
    request.project.bytes = project
        .replacen(
            entities,
            r#""entities":[{"id":"note","primaryDataset":"planner-package","route":"notes","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}]},"#,
            1,
        )
        .into_bytes();
    request.from_package_digest = Some(predecessor.package_digest().to_owned());
    request.migration_plan = PackageMigrationPlanInput::SuccessorFromBaseline {
        prior_baseline: Box::new(predecessor.migration_baseline().clone()),
    };
    let successor = prepare_package_with_project_assets(request, vec![planner_asset()])
        .expect("an additive successor of a planner package prepares");

    let changes = compiled_registry_change_set_from_baseline(
        predecessor.migration_baseline(),
        successor.registry(),
        predecessor.package_digest(),
    );
    assert_eq!(
        changes
            .changes
            .iter()
            .map(|change| (
                change.code,
                change.target.entity_id.as_deref(),
                change.target.member_id.as_deref()
            ))
            .collect::<Vec<_>>(),
        vec![(CompiledRegistryChangeCode::EntityAdded, Some("note"), None)],
        "the unchanged planner contributes no change to the successor"
    );
    assert_eq!(
        successor
            .manifest()
            .migration_plan
            .from_package_digest
            .as_deref(),
        Some(predecessor.package_digest())
    );

    let successor_package = root.path().join("successor");
    successor.publish_to_directory(&successor_package).unwrap();
    load_predecessor_package(&successor_package, &context)
        .expect("the successor is itself a readable predecessor");
}

#[test]
fn geojson_binding_changes_are_classified_as_disclosure_even_for_get_only_profiles() {
    for (previous_binding, candidate_binding) in [
        (None, Some("location")),
        (Some("location"), None),
        (Some("location"), Some("alternate")),
    ] {
        let previous = compile_source(&geojson_source(previous_binding));
        let candidate = compile_source(&geojson_source(candidate_binding));
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
    let previous = compile_source(&geojson_source(None));
    let source = geojson_source(Some("location"));
    let candidate = compile_source(&source);
    let migrations = vec![metadata_only_source_between(&previous, &candidate)];
    let package = prepare_package(build_request(
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
    let compiled = compile_variant(Variant::Base);
    let baseline = registry_breg::package::CompiledRegistryMigrationBaseline::from_compiled(
        PRIOR_REVISION,
        &compiled,
    );
    let value = serde_json::to_value(&baseline).expect("baseline serializes");
    let bytes = canonicalize_json(&value).expect("baseline canonicalizes");
    let parsed: registry_breg::package::CompiledRegistryMigrationBaseline =
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
    let source_with_span = |span: serde_json::Value, add_field| {
        let source = spatial_source("location", true);
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
            project_bytes: project_bytes(&module_digest(&module)),
            module_bytes,
        }
    };
    let previous = compile_source(&source_with_span(json!(1.0), false));
    let equivalent = compile_source(&source_with_span(json!(1), false));
    assert!(
        compiled_registry_change_set(&previous, &equivalent, PRIOR_REVISION)
            .changes
            .is_empty()
    );

    let baseline = registry_breg::package::CompiledRegistryMigrationBaseline::from_compiled(
        PRIOR_REVISION,
        &previous,
    );
    let reloaded: registry_breg::package::CompiledRegistryMigrationBaseline =
        serde_json::from_slice(&canonical(&baseline)).unwrap();
    assert_eq!(
        baseline, reloaded,
        "signed numeric normalization preserves equality"
    );

    let source = source_with_span(json!(1.0), true);
    let package = prepare_package(build_request(
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
    let previous = compile_source(&spatial_source("location", false));
    let source = spatial_source("location", true);
    let candidate = compile_source(&source);
    let package = prepare_spatial_successor(previous, source, &candidate);
    let statements = &package.manifest().migration_plan.statements;
    assert_eq!(statements.len(), 5);
    assert!(statements[0].sql.starts_with("DROP POLICY "));
    assert!(statements[0].sql.contains("registry_rls_select_"));
    assert!(statements[1]
        .sql
        .contains("CREATE OR REPLACE FUNCTION registry_context.spatial_bbox_geometry"));
    assert!(statements[2].sql.contains("ADD COLUMN"));
    assert!(statements[2].sql.contains("GENERATED ALWAYS AS"));
    assert!(statements[2]
        .sql
        .contains("registry_spatial_ext.geometry(Point,4326)"));
    assert!(statements[3].sql.contains("USING gist"));
    assert_eq!(statements[4].id, "entity.asset.spatial-candidates-view");
    assert!(statements[4]
        .sql
        .starts_with("CREATE VIEW registry_context."));
    assert!(statements[4]
        .sql
        .contains("security_invoker=false, security_barrier=true"));
    assert!(!statements
        .iter()
        .any(|statement| statement.sql.contains("CREATE EXTENSION")));
}

#[cfg(feature = "tooling")]
#[test]
fn reviewed_bbox_removal_drops_candidates_and_policy_before_internal_projection() {
    let previous = compile_source(&spatial_source("location", true));
    let logical_point_column = previous.entities()["asset"].fields["location"]
        .physical_name
        .clone();
    let source = spatial_source("location", false);
    let candidate = compile_source(&source);
    let package = prepare_spatial_successor(previous, source, &candidate);
    let statements = &package.manifest().migration_plan.statements;
    assert_eq!(statements.len(), 6);
    assert!(statements[0].sql.starts_with("DROP POLICY"));
    assert!(statements[0].sql.contains("registry_rls_select_"));
    assert!(statements[1].sql.starts_with("DROP POLICY"));
    assert!(statements[1].sql.contains("registry_spatial_bbox_rls_"));
    assert_eq!(
        statements[2].id,
        "entity.asset.spatial-candidates-view.drop"
    );
    assert!(statements[2]
        .sql
        .starts_with("DROP VIEW IF EXISTS registry_context."));
    assert!(statements[3].sql.starts_with("DROP INDEX"));
    assert!(statements[4].sql.contains("DROP COLUMN"));
    assert!(statements[5].sql.starts_with("DROP FUNCTION"));
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
    let previous = compile_source(&spatial_source("location", true));
    let source = spatial_source("alternate", true);
    let candidate = compile_source(&source);
    let package = prepare_spatial_successor(previous, source, &candidate);
    let statements = &package.manifest().migration_plan.statements;
    assert_eq!(statements.len(), 7);
    assert!(statements[0].sql.starts_with("DROP POLICY"));
    assert!(statements[0].sql.contains("registry_spatial_bbox_rls_"));
    assert_eq!(
        statements[1].id,
        "entity.asset.spatial-candidates-view.drop"
    );
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
    let previous = compile_source(&spatial_source("location", true));
    let source = spatial_source("location", true);
    let mut module: serde_json::Value = serde_json::from_slice(&source.module_bytes).unwrap();
    module["entities"][0]["accessProfiles"][0]["spatialQueries"]["bbox"]
        ["maximumLongitudeSpanDegrees"] = json!(0.25);
    let module_bytes = serde_json::to_vec(&module).unwrap();
    let parsed_module = parse_module_yaml(&module_bytes).unwrap();
    let source = SourceFixture {
        project_bytes: project_bytes(&module_digest(&parsed_module)),
        module_bytes,
    };
    let candidate = compile_source(&source);
    let package = prepare_spatial_successor(previous, source, &candidate);
    let statements = &package.manifest().migration_plan.statements;
    assert_eq!(statements.len(), 3);
    assert!(statements[0].sql.starts_with("DROP POLICY"));
    assert!(statements[0].sql.contains("registry_spatial_bbox_rls_"));
    assert_eq!(
        statements[1].id,
        "entity.asset.spatial-candidates-view.drop"
    );
    assert_eq!(statements[2].id, "entity.asset.spatial-candidates-view");
    let candidate_definition = candidate
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.asset.spatial-candidates-view")
        .unwrap();
    assert_eq!(statements[2], *candidate_definition);
}

#[cfg(feature = "tooling")]
#[test]
fn reviewed_source_view_refresh_preserves_candidate_drop_and_recreation() {
    let previous = compile_source(&spatial_source("location", true));
    let source = spatial_source("location", true);
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
        project_bytes: project_bytes(&module_digest(&parsed_module)),
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
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::OptionalField);

    let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
    assert_eq!(change_set.changes.len(), 1);
    assert_change(
        &change_set,
        CompiledRegistryChangeClass::CompatibleAdditive,
        CompiledRegistryChangeCode::FieldAddedOptional,
    );
    let plan = change_set_to_applicable_migration_plan(&change_set)
        .expect("optional field change is applicable");
    assert_eq!(plan.from_package_digest.as_deref(), Some(PRIOR_REVISION));
    assert_eq!(
        plan.prior_baseline
            .as_ref()
            .map(|baseline| baseline.package_digest.as_str()),
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
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::NewEntity);
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
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::ReferenceConstraintIndex);
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
            "entity.asset.index.reference:site",
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
        let previous = compile_variant(previous_variant);
        let candidate = compile_variant(candidate_variant);
        let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
        assert_change(&change_set, class, code);
        assert_eq!(change_set.migration_plan, None);
        assert!(change_set_to_applicable_migration_plan(&change_set).is_err());
    }
}

#[test]
fn vocabulary_code_additions_are_additive_and_replace_the_column_check() {
    let previous = vocabulary_registry("status", &["open", "closed"]);
    let candidate = vocabulary_registry("status", &["open", "closed", "archived"]);
    let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);

    assert_eq!(change_set.changes.len(), 1, "{:#?}", change_set.changes);
    assert_change(
        &change_set,
        CompiledRegistryChangeClass::CompatibleAdditive,
        CompiledRegistryChangeCode::FieldVocabularyCodesAdded,
    );
    let plan = change_set_to_applicable_migration_plan(&change_set)
        .expect("a vocabulary code addition is applicable");
    let ids = plan
        .statements
        .iter()
        .map(|statement| statement.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["entity.entry.field.status.vocabulary"]);
    let sql = &plan.statements[0].sql;
    assert!(
        sql.contains("'archived'") && sql.contains("DROP CONSTRAINT"),
        "the statement replaces the column check with the candidate codes: {sql}"
    );
    assert!(
        sql.starts_with("DO $breg_vocabulary$\n") && sql.ends_with("$breg_vocabulary$"),
        "the vocabulary statement keeps its quoting tag: {sql}"
    );

    for (candidate, reason) in [
        (
            vocabulary_registry("status", &["open"]),
            "removing a code can strand existing rows",
        ),
        (
            vocabulary_registry("state", &["open", "closed"]),
            "pointing the field at another vocabulary is not an addition",
        ),
    ] {
        let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
        assert!(
            change_set.changes.iter().any(|change| {
                change.class == CompiledRegistryChangeClass::DestructiveOrIrreversible
                    && change.code == CompiledRegistryChangeCode::FieldTypeChanged
            }),
            "{reason}: {:#?}",
            change_set.changes
        );
        assert_eq!(change_set.migration_plan, None, "{reason}");
        assert!(
            change_set_to_applicable_migration_plan(&change_set).is_err(),
            "{reason}"
        );
    }
}

#[test]
fn text_length_widening_is_additive_and_replaces_the_length_check() {
    for pattern in [None, Some("^[a-z ]*$")] {
        let previous = length_registry("text", 80, pattern);
        let candidate = length_registry("text", 200, pattern);
        let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);

        assert_eq!(change_set.changes.len(), 1, "{:#?}", change_set.changes);
        assert_change(
            &change_set,
            CompiledRegistryChangeClass::CompatibleAdditive,
            CompiledRegistryChangeCode::FieldLengthWidened,
        );
        let plan = change_set_to_applicable_migration_plan(&change_set)
            .expect("a raised text length limit is applicable");
        let ids = plan
            .statements
            .iter()
            .map(|statement| statement.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["entity.entry.field.note.length"]);
        let sql = &plan.statements[0].sql;
        assert!(
            sql.contains("<= 200") && sql.contains("DROP CONSTRAINT"),
            "the statement replaces the length check with the candidate limit: {sql}"
        );
        assert!(
            sql.starts_with("DO $breg_length$\n") && sql.ends_with("$breg_length$"),
            "the statement's quoting tag names the check it replaces: {sql}"
        );
        assert_eq!(
            sql.contains("breg_pattern_"),
            pattern.is_some(),
            "a field pattern's check is excluded from the replaced check: {sql}"
        );
    }

    for (previous, candidate, reason) in [
        (
            length_registry("text", 80, None),
            length_registry("text", 40, None),
            "a lowered text limit can strand stored values",
        ),
        (
            length_registry("string", 80, None),
            length_registry("string", 200, None),
            "a string maxLength is its varchar column type",
        ),
    ] {
        let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
        assert!(
            change_set.changes.iter().any(|change| {
                change.class == CompiledRegistryChangeClass::DestructiveOrIrreversible
                    && change.code == CompiledRegistryChangeCode::FieldTypeChanged
            }),
            "{reason}: {:#?}",
            change_set.changes
        );
        assert_eq!(change_set.migration_plan, None, "{reason}");
    }
}

#[test]
fn string_minimum_lowering_is_additive_and_replaces_or_drops_the_length_check() {
    for pattern in [None, Some("^[a-z ]*$")] {
        for (lowered, expected, drops) in [(2, ">= 2", false), (0, "DROP CONSTRAINT %I'", true)] {
            let previous = string_length_registry(5, 80, pattern);
            let candidate = string_length_registry(lowered, 80, pattern);
            let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);

            assert_eq!(change_set.changes.len(), 1, "{:#?}", change_set.changes);
            assert_change(
                &change_set,
                CompiledRegistryChangeClass::CompatibleAdditive,
                CompiledRegistryChangeCode::FieldLengthWidened,
            );
            let plan = change_set_to_applicable_migration_plan(&change_set)
                .expect("a lowered string minimum is applicable");
            let ids = plan
                .statements
                .iter()
                .map(|statement| statement.id.as_str())
                .collect::<Vec<_>>();
            assert_eq!(ids, vec!["entity.entry.field.note.length"]);
            let sql = &plan.statements[0].sql;
            assert!(
                sql.contains(expected),
                "the statement lowers the minimum to {lowered}: {sql}"
            );
            assert_eq!(
                sql.contains("ADD CONSTRAINT"),
                !drops,
                "a zero minimum drops the check a fresh install never creates: {sql}"
            );
            assert!(
                sql.starts_with("DO $breg_length$\n") && sql.ends_with("$breg_length$"),
                "the statement's quoting tag names the check it replaces: {sql}"
            );
            assert_eq!(
                sql.contains("breg_pattern_"),
                pattern.is_some(),
                "a field pattern's check is excluded from the replaced check: {sql}"
            );
        }
    }

    for (previous, candidate, reason) in [
        (
            string_length_registry(2, 80, None),
            string_length_registry(5, 80, None),
            "a raised string minimum can strand stored values",
        ),
        (
            string_length_registry(5, 80, None),
            string_length_registry(2, 200, None),
            "a string maxLength is its varchar column type",
        ),
    ] {
        let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
        assert!(
            change_set.changes.iter().any(|change| {
                change.class == CompiledRegistryChangeClass::DestructiveOrIrreversible
                    && change.code == CompiledRegistryChangeCode::FieldTypeChanged
            }),
            "{reason}: {:#?}",
            change_set.changes
        );
        assert_eq!(change_set.migration_plan, None, "{reason}");
    }
}

#[test]
fn plaintext_to_encrypted_type_change_is_unsupported() {
    let previous = compile_variant(Variant::PlaintextSecret);
    let candidate = compile_variant(Variant::EncryptedStructuredSecret);
    let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);

    assert_eq!(change_set.changes.len(), 2);
    assert_change(
        &change_set,
        CompiledRegistryChangeClass::DataBackfillRequired,
        CompiledRegistryChangeCode::FieldEncryptionChanged,
    );
    assert_change(
        &change_set,
        CompiledRegistryChangeClass::Unsupported,
        CompiledRegistryChangeCode::FieldTypeChanged,
    );
    assert_eq!(change_set.migration_plan, None);
    assert!(change_set_to_applicable_migration_plan(&change_set).is_err());
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
        let previous = compile_variant(previous_variant);
        let candidate = compile_variant(candidate_variant);
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
    let event_module = parse_module_yaml(br#"{"id":"event-extension","version":"1","extendEntities":[{"entity":"asset","accessProfiles":[{"id":"auditor","principalClaim":"principal","operations":["get","list"],"readableFields":["code","status"],"writableFields":[], "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}],"hooks":[{"phase":"after","id":"asset-created","trigger":"created","projection":["code","status"],"handler":{"kind":"url","destinationId":"package-change-events"}}]}],"entities":[{"id":"site","primaryDataset":"neutral-registry","route":"sites","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"], "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}]}]}"#)
        .expect("event extension parses");
    let project_bytes = format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}}},"publicService":{{"id":"neutral-registry-service","title":"Neutral Registry Catalog"}},"datasets":[{{"id":"neutral-registry","title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"neutral-registry-data-service","title":"Neutral Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["neutral-registry"]}}]}},"entities":[{{"id":"asset","primaryDataset":"neutral-registry","route":"assets","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":8,"classification":"internal"}}]}}],"accessProfiles":[{{"id":"reader","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":[{{"rowBoundaries": "unrestricted", "entity":"asset","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}}]}}],"modules":[{{"id":"field-extension","version":"1","digest":"{}"}},{{"id":"event-extension","version":"1","digest":"{}"}}]}}"#,
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
    assert!(asset.hooks.contains_key("asset-created"));
    assert!(first.entities().contains_key("site"));
}

#[test]
fn equivalent_reordered_inputs_produce_stable_change_and_statement_inventory() {
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::ReferenceConstraintIndex);
    let reordered = compile_variant(Variant::ReferenceConstraintIndexReordered);
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
    let previous_source = source_for_variant(Variant::Base);
    let previous_package = registry_breg::package::prepare_package(build_request(
        None,
        previous_source.project_bytes,
        previous_source.module_bytes,
        PackageMigrationPlanInput::InitialCompiledDdl,
    ))
    .expect("initial package prepares");
    let prior_revision = previous_package.package_digest().unwrap().to_owned();

    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::ReferenceConstraintIndex);
    let expected = compiled_registry_change_set(&previous, &candidate, &prior_revision);
    let expected_plan = change_set_to_applicable_migration_plan(&expected)
        .expect("candidate additive plan is applicable");

    let candidate_source = source_for_variant(Variant::ReferenceConstraintIndex);
    let successor = registry_breg::package::prepare_package(build_request(
        Some(&prior_revision),
        candidate_source.project_bytes,
        candidate_source.module_bytes,
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(previous),
        },
    ))
    .expect("successor closed plan validates");
    assert_eq!(
        successor
            .manifest()
            .migration_plan
            .from_package_digest
            .as_deref(),
        Some(prior_revision.as_str())
    );
    assert_eq!(successor.manifest().migration_plan, expected_plan);
}

#[test]
fn derived_sql_asset_bytes_change_revisions_and_emit_generated_view_replacement() {
    let previous_source = derived_source_for_sql(
        b"SELECT a.id AS id, a.code AS summary FROM registry_source.asset a",
    );
    let previous = compile_derived_source(&previous_source);
    let previous_package = registry_breg::package::prepare_package(derived_build_request(
        &previous_source,
        None,
        None,
    ))
    .expect("initial derived package prepares");

    let candidate_source = derived_source_for_sql(
        b"SELECT a.id AS id, (a.code) AS summary FROM registry_source.asset a",
    );
    let candidate = compile_derived_source(&candidate_source);
    let successor = registry_breg::package::prepare_package(derived_build_request(
        &candidate_source,
        Some(&previous),
        Some(previous_package.package_digest().unwrap().as_str()),
    ))
    .expect("successor derived package prepares");

    assert_ne!(
        previous.module_closure()[0].digest,
        candidate.module_closure()[0].digest
    );
    assert_ne!(previous.revision(), candidate.revision());
    assert_ne!(
        previous_package.package_digest().unwrap(),
        successor.package_digest().unwrap()
    );
    assert!(successor
        .file_bytes()
        .contains_key("source/modules/core/sql/summary.sql"));
    assert!(successor.manifest().files.iter().any(|entry| {
        entry.path == "source/modules/core/sql/summary.sql"
            && entry.role == registry_breg::package::PackageFileRole::SourceModuleAsset
    }));

    let change_set = compiled_registry_change_set(
        &previous,
        &candidate,
        &previous_package.package_digest().unwrap(),
    );
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
fn unchanged_derived_relation_emits_compiler_owned_view_replacement() {
    let source = derived_source_for_sql(
        b"SELECT a.id AS id, a.code AS summary FROM registry_source.asset a",
    );
    let previous = compile_derived_source(&source);
    let candidate = compile_derived_source(&source);
    let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);

    assert!(
        change_set.changes.is_empty(),
        "unchanged authored input has no model change"
    );
    let plan = change_set_to_applicable_migration_plan(&change_set)
        .expect("a compiler-owned derived wrapper is refreshable");
    let [replacement] = plan.statements.as_slice() else {
        panic!("one retained derived relation emits one view replacement");
    };
    assert_eq!(replacement.id, "entity.asset.derived.summary.view");
    assert!(replacement.sql.starts_with("CREATE OR REPLACE VIEW "));
    assert_eq!(
        replacement
            .sql
            .strip_prefix("CREATE OR REPLACE VIEW ")
            .expect("successor uses replacement DDL"),
        candidate
            .ddl()
            .statements
            .iter()
            .find(|statement| statement.id == replacement.id)
            .and_then(|statement| statement.sql.strip_prefix("CREATE VIEW "))
            .expect("candidate carries the generated derived view")
    );
}

#[cfg(feature = "tooling")]
#[test]
fn unrelated_reviewed_change_rebuilds_every_view_around_a_retained_derived_relation() {
    let previous_source = derived_source_for_sql(
        b"SELECT a.id AS id, a.code AS summary FROM registry_source.asset a",
    );
    let previous = compile_derived_source(&previous_source);
    let mut module: serde_json::Value =
        serde_json::from_slice(&previous_source.module_bytes).expect("derived module parses");
    module["entities"][0]["route"] = json!("equipment");
    let module_bytes = serde_json::to_vec(&module).expect("derived module serializes");
    let parsed_module = parse_module_yaml(&module_bytes).expect("derived module reparses");
    let candidate_source = DerivedSourceFixture {
        project_bytes: project_bytes(&module_digest_with_assets(
            &parsed_module,
            &[ModuleAssetSource {
                module: Some("core".to_owned()),
                path: "sql/summary.sql".to_owned(),
                bytes: previous_source.sql.clone(),
            }],
        )),
        module_bytes,
        sql: previous_source.sql.clone(),
    };
    let candidate = compile_derived_source(&candidate_source);
    let migration = metadata_only_source_between(&previous, &candidate);
    let mut request =
        derived_build_request(&candidate_source, Some(&previous), Some(PRIOR_REVISION));
    request.migration_plan = PackageMigrationPlanInput::ReviewedSuccessor {
        prior_registry: Box::new(previous),
        prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
        migrations: vec![migration],
    };
    let reviewed =
        prepare_package(request).expect("unrelated reviewed successor refreshes its read views");
    // The reviewed executor drops every managed read view once the plan
    // carries a non-spatial view statement, so a retained derived relation
    // brings the complete candidate view set, its source views included.
    let planned_views = reviewed
        .manifest()
        .migration_plan
        .statements
        .iter()
        .filter(|statement| statement.kind == registry_breg::generated_ddl::DdlStatementKind::View)
        .map(|statement| (statement.id.as_str(), statement.sql.as_str()))
        .collect::<Vec<_>>();
    let candidate_views = candidate
        .ddl()
        .statements
        .iter()
        .filter(|statement| statement.kind == registry_breg::generated_ddl::DdlStatementKind::View)
        .map(|statement| (statement.id.as_str(), statement.sql.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(planned_views, candidate_views);
    assert!(planned_views
        .iter()
        .any(|(_, sql)| sql.starts_with("CREATE VIEW registry_source.")));
    assert_eq!(
        planned_views
            .iter()
            .filter(|(id, _)| *id == "entity.asset.derived.summary.view")
            .count(),
        1
    );
}

#[test]
fn oversized_derived_sql_asset_is_refused_before_compilation() {
    let mut source = derived_source_for_sql(
        b"SELECT a.id AS id, a.code AS summary FROM registry_source.asset a",
    );
    source.sql = vec![b'x'; 256 * 1024 + 1];
    let module = parse_module_yaml(&source.module_bytes).expect("derived module parses");
    source.project_bytes = project_bytes(&module_digest_with_assets(
        &module,
        &[ModuleAssetSource {
            module: Some("core".to_owned()),
            path: "sql/summary.sql".to_owned(),
            bytes: source.sql.clone(),
        }],
    ));

    assert_eq!(
        registry_breg::package::prepare_package(derived_build_request(&source, None, None)).err(),
        Some(registry_breg::package::PackageError::Derivation)
    );
}

#[cfg(feature = "tooling")]
#[test]
fn metadata_only_policy_surface_can_apply_automatically_and_be_reviewed_without_dummy_sql() {
    let previous = compile_variant(Variant::MetadataOnlyBase);
    let candidate = compile_variant(Variant::MetadataOnlyChanged);
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

    let source = source_for_variant(Variant::MetadataOnlyChanged);
    let reviewed = prepare_package(build_request(
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
    let previous = compile_variant(Variant::ReferenceTargetBase);
    let candidate = compile_variant(Variant::ReferenceTargetChanged);
    let change_set = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
    assert_change(
        &change_set,
        CompiledRegistryChangeClass::DestructiveOrIrreversible,
        CompiledRegistryChangeCode::ReferenceTargetChanged,
    );
    assert!(change_set_to_applicable_migration_plan(&change_set).is_err());

    let source = source_for_variant(Variant::ReferenceTargetChanged);
    let reviewed = prepare_package(build_request(
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
    let initial_source = source_for_variant(Variant::Base);
    let initial = prepare_package(build_request(
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
            "hasPredecessor": false,
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

    let additive_source = source_for_variant(Variant::OptionalField);
    let additive = prepare_package(build_request(
        Some(PRIOR_REVISION),
        additive_source.project_bytes,
        additive_source.module_bytes,
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(compile_variant(Variant::Base)),
        },
    ))
    .expect("additive package prepares");
    let inspected_additive = inspect_prepared(&additive);
    assert_eq!(
        serde_json::to_value(inspected_additive.migration_summary())
            .expect("additive summary serializes"),
        json!({
            "planKind": "compatible_additive",
            "hasPredecessor": true,
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
        "hasPredecessor": true,
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

    let candidate = compile_variant(Variant::RequiredAndOptionalFields);
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
    let source = source_for_variant(Variant::Base);
    let prepared = prepare_package(build_request(
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
        .publish_to_directory(&package)
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

/// A plain registry whose one entity stores a code from `vocabulary`. The
/// project's `status` vocabulary holds `values`; its `state` vocabulary always
/// holds open, closed, and archived.
fn vocabulary_registry(vocabulary: &str, values: &[&str]) -> CompiledRegistry {
    let project = serde_json::json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {
            "id": "vocabulary-catalog",
            "version": "1",
            "defaultLanguage": "en",
            "canonicalBaseIri": "https://authoring.example.test"
        },
        "vocabularies": [
            {"id": "status", "values": values},
            {"id": "state", "values": ["open", "closed", "archived"]}
        ],
        "entities": [{
            "id": "entry",
            "primaryDataset": "test-dataset",
            "route": "entries",
            "mutationMode": "mutable",
            "fields": [
                {
                    "id": "status",
                    "type": "vocabulary-code",
                    "vocabulary": vocabulary,
                    "required": true,
                    "classification": "internal"
                }
            ]
        }],
        "accessProfiles": [{
            "id": "writer",
            "default": true,
            "principalClaim": "registry_principal",
            "requiredScopes": "unrestricted",
            "permissions": [{
                "entity": "entry",
                "operations": ["create", "get", "list", "patch"],
                "readableFields": ["status"],
                "writableFields": ["status"],
                "rowBoundaries": "unrestricted"
            }]
        }]
    });
    let bytes = serde_json::to_vec(&project).expect("fixture serializes");
    let project = parse_project_json(&bytes).expect("vocabulary fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("vocabulary fixture compiles")
}

fn length_registry(field_type: &str, max_length: u32, pattern: Option<&str>) -> CompiledRegistry {
    let mut field = serde_json::json!({
        "id": "note",
        "type": field_type,
        "maxLength": max_length,
        "required": true,
        "classification": "internal"
    });
    if let Some(pattern) = pattern {
        field["pattern"] = serde_json::json!(pattern);
    }
    field_registry(field)
}

/// A `string` field with the given `minLength` and `maxLength`.
fn string_length_registry(
    min_length: u32,
    max_length: u32,
    pattern: Option<&str>,
) -> CompiledRegistry {
    let mut field = serde_json::json!({
        "id": "note",
        "type": "string",
        "minLength": min_length,
        "maxLength": max_length,
        "required": true,
        "classification": "internal"
    });
    if let Some(pattern) = pattern {
        field["pattern"] = serde_json::json!(pattern);
    }
    field_registry(field)
}

fn field_registry(field: serde_json::Value) -> CompiledRegistry {
    let project = serde_json::json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {
            "id": "length-catalog",
            "version": "1",
            "defaultLanguage": "en",
            "canonicalBaseIri": "https://authoring.example.test"
        },
        "entities": [{
            "id": "entry",
            "primaryDataset": "test-dataset",
            "route": "entries",
            "mutationMode": "mutable",
            "fields": [field]
        }],
        "accessProfiles": [{
            "id": "writer",
            "default": true,
            "principalClaim": "registry_principal",
            "requiredScopes": "unrestricted",
            "permissions": [{
                "entity": "entry",
                "operations": ["create", "get", "list", "patch"],
                "readableFields": ["note"],
                "writableFields": ["note"],
                "rowBoundaries": "unrestricted"
            }]
        }]
    });
    let bytes = serde_json::to_vec(&project).expect("fixture serializes");
    let project = parse_project_json(&bytes).expect("length fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("length fixture compiles")
}

fn assert_change(
    change_set: &registry_breg::package::CompiledRegistryChangeSet,
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
    PlaintextSecret,
    EncryptedStructuredSecret,
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

fn compile_variant(variant: Variant) -> CompiledRegistry {
    let source = source_for_variant(variant);
    let module = parse_module_yaml(&source.module_bytes).expect("fixture module parses");
    let project = parse_project_yaml(&source.project_bytes).expect("fixture project parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("fixture compiles in production")
}

fn source_for_variant(variant: Variant) -> SourceFixture {
    let module_bytes = module_bytes(variant);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses for digest");
    let digest = module_digest(&module);
    SourceFixture {
        project_bytes: project_bytes(&digest),
        module_bytes,
    }
}

fn compile_source(source: &SourceFixture) -> CompiledRegistry {
    let module = parse_module_yaml(&source.module_bytes).expect("fixture module parses");
    let project = parse_project_yaml(&source.project_bytes).expect("fixture project parses");
    compile_project(&project, &[module], CompileProfile::Production).expect("fixture compiles")
}

fn geojson_source(binding: Option<&str>) -> SourceFixture {
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
        project_bytes: project_bytes(&module_digest(&module)),
        module_bytes,
    }
}

#[cfg(feature = "tooling")]
fn spatial_source(binding: &str, bbox: bool) -> SourceFixture {
    let source = geojson_source(Some(binding));
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
        project_bytes: project_bytes(&module_digest(&module)),
        module_bytes,
    }
}

fn project_bytes(module_digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}}},"publicService":{{"id":"neutral-registry-service","title":"Neutral Registry Catalog"}},"datasets":[{{"id":"neutral-registry","title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"neutral-registry-data-service","title":"Neutral Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["neutral-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    )
    .into_bytes()
}

fn derived_source_for_sql(sql: &[u8]) -> DerivedSourceFixture {
    let module_bytes = br#"{"id":"core","version":"1","entities":[{"id":"asset","primaryDataset":"neutral-registry","route":"assets","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"derived":[{"id":"summary","sql":"sql/summary.sql","key":"id","fields":[{"id":"summary","type":"string","maxLength":16,"classification":"internal"}]}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code","summary"], "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}]}]}"#.to_vec();
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
        project_bytes: project_bytes(&digest),
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
    prior_registry: Option<&CompiledRegistry>,
    prior_revision: Option<&str>,
) -> PackageBuildRequest {
    let mut request = build_request(
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
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::RequiredField => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"batch","type":"string","maxLength":16,"required":true,"classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::RequiredAndOptionalFields => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"batch","type":"string","maxLength":16,"required":true,"classification":"internal"},{"id":"color","type":"string","maxLength":16,"classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::ReferenceConstraintIndex => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"site","type":"reference","target":"site","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            r#","constraints":[{"kind":"unique","id":"code-unique","fields":["code"]}]"#,
            r#","indexes":[{"id":"code-idx","fields":["code"]}]"#,
            "",
        ),
        Variant::ReferenceConstraintIndexReordered => asset_entity(
            r#"{"id":"site","type":"reference","target":"site","classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"code","type":"string","maxLength":8,"classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["list","get","create"],"writableFields":["code"],"readableFields":["code"]"#,
            r#","constraints":[{"fields":["code"],"id":"code-unique","kind":"unique"}]"#,
            r#","indexes":[{"fields":["code"],"id":"code-idx"}]"#,
            "",
        ),
        Variant::FieldRemoved => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::TypeChanged => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"string","maxLength":8,"classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::PlaintextSecret => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"secret","type":"string","maxLength":64,"classification":"restricted"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::EncryptedStructuredSecret => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"secret","type":"structured","maxBytes":1024,"schema":{"type":"object","additionalProperties":false},"classification":"restricted","encrypted":true}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::RouteChanged => asset_entity(
            base_asset_fields(),
            r#""route":"equipment""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::EntityClassificationChanged => asset_entity(
            base_asset_fields(),
            r#""route":"assets","classification":"restricted""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::ClassificationChanged => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"restricted"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::AuthorizationChanged => asset_entity(
            base_asset_fields(),
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"subject","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::MutationModeChanged => asset_entity_with_mode(
            base_asset_fields(),
            r#""route":"assets""#,
            "mutable",
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::TemporalChanged => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"required":true,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"valid-from","type":"date","required":true,"classification":"internal"},{"id":"valid-to","type":"date","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code","valid-from","valid-to"],"writableFields":["code","valid-from","valid-to"]"#,
            r#","constraints":[{"kind":"temporal-non-overlap","id":"code-time","scopeFields":["code"],"startField":"valid-from","endField":"valid-to"}]"#,
            "",
            r#","temporal":{"startField":"valid-from","endField":"valid-to","scopeFields":["code"]}"#,
        ),
        Variant::TemporalRoleBase => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"valid-from","type":"date","required":true,"classification":"internal"},{"id":"valid-to","type":"date","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code","valid-from","valid-to"],"writableFields":["code","valid-from","valid-to"]"#,
            "",
            "",
            "",
        ),
        Variant::TemporalRoleChanged => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"valid-from","type":"date","required":true,"classification":"internal","validTimeRole":"valid_from"},{"id":"valid-to","type":"date","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code","valid-from","valid-to"],"writableFields":["code","valid-from","valid-to"]"#,
            "",
            "",
            "",
        ),
        Variant::RankRequired => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","required":true,"classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::ReferenceTargetBase => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"home-site","type":"reference","target":"site","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::ReferenceTargetChanged => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"home-site","type":"reference","target":"location","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
            "",
            "",
            "",
        ),
        Variant::MetadataOnlyBase => asset_entity(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"internal"},{"id":"valid-from","type":"date","required":true,"classification":"internal"},{"id":"valid-to","type":"date","classification":"internal"}"#,
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code","valid-from","valid-to"],"writableFields":["code","valid-from","valid-to"]"#,
            "",
            "",
            r#","hooks":[{"phase":"after","id":"asset-created","trigger":"created","projection":["code"],"handler":{"kind":"url","destinationId":"package-change-events"}}]"#,
        ),
        Variant::MetadataOnlyChanged => asset_entity_with_mode(
            r#"{"id":"code","type":"string","maxLength":8,"classification":"internal"},{"id":"rank","type":"int64","classification":"restricted"},{"id":"valid-from","type":"date","required":true,"classification":"internal","validTimeRole":"valid_from"},{"id":"valid-to","type":"date","classification":"internal"}"#,
            r#""route":"equipment","classification":"restricted","accessRequirements":{"requiredScopes":["asset:read"]}"#,
            "mutable",
            r#""id":"reader","principalClaim":"subject","requiredScopes":["asset:read"],"operations":["create","get","list"],"readableFields":["code","valid-from","valid-to"],"writableFields":["code","valid-from","valid-to"]"#,
            "",
            "",
            r#","hooks":[{"phase":"after","id":"asset-created","trigger":"created","projection":["code","rank"],"handler":{"kind":"url","destinationId":"package-change-events"}}]"#,
        ),
        Variant::Base | Variant::NewEntity => asset_entity(
            base_asset_fields(),
            r#""route":"assets""#,
            r#""id":"reader","requiredScopes":"unrestricted","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]"#,
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
        r#"{{"id":"asset","primaryDataset":"neutral-registry",{route},"mutationMode":"{mutation_mode}","fields":[{fields}]{constraints}{indexes},"accessProfiles":[{{"rowBoundaries":"unrestricted",{access}}}]{temporal}}}"#
    )
}

fn site_entity() -> &'static str {
    r#"{"id":"site","primaryDataset":"neutral-registry","route":"sites","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"], "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}]}"#
}

fn location_entity() -> &'static str {
    r#"{"id":"location","primaryDataset":"neutral-registry","route":"locations","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"], "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}]}"#
}

fn placement_entity() -> &'static str {
    r#"{"id":"placement","primaryDataset":"neutral-registry","route":"placements","mutationMode":"create_only","fields":[{"id":"asset","type":"reference","target":"asset","required":true,"classification":"internal"},{"id":"site","type":"reference","target":"site","required":true,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["asset","site"],"writableFields":["asset","site"], "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}]}"#
}

fn build_request(
    prior_revision: Option<&str>,
    project_bytes: Vec<u8>,
    module_bytes: Vec<u8>,
    migration_plan: PackageMigrationPlanInput,
) -> PackageBuildRequest {
    PackageBuildRequest {
        from_package_digest: prior_revision.map(str::to_owned),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint:
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
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
          "package":{{"sourceRevision":"{SOURCE_REVISION}"}},
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
              "review":{{"authority":"casework-main","policyId":"request-review"}},
              "onApproved":{{"mode":"manual"}}
            }}
          }}],
          "accessProfiles":[{{
            "id":"operator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":[
              {{"rowBoundaries": "unrestricted", "entity":"target","operations":["get","list"],"readableFields":["label"]}},
              {{"rowBoundaries": "unrestricted", "entity":"request","operations":["create","patch","get","list","submit_request","revise_request","cancel_request","apply_request"],"readableFields":["target","label"],"writableFields":["target","label"],
                "applyTargets":[{{"rowBoundaries": "unrestricted", "entity":"target"}}]
              }}
            ]
          }}]
        }}"#
    )
    .into_bytes();
    PackageBuildRequest {
        from_package_digest: None,
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint:
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project,
        },
        modules: Vec::new(),
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: b"apiVersion: id.registrystack.org/formats/breg/journeys/v1\nkind: BRegJourneys\njourneys: []\n"
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
        "accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["label"], "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}]
      },{
        "id":"request","primaryDataset":"planner-package","route":"requests","mutationMode":"mutable",
        "fields":[
          {"id":"target","type":"reference","target":"target","required":true,"classification":"internal"},
          {"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}
        ],
        "changeRequest":{
          "planner":{"kind":"rhai","script":"planners/request.rhai","abi":"registry.change-request-plan/v1","requestFields":["target","label"],"writes":[{"target":{"fromField":"target"},"operation":"patch","fields":["label"]}]},
          "review":{"authority":"casework-main","policyId":"request-review"},
          "onApproved":{"mode":"manual"}
        },
        "accessProfiles":[{"id":"operator","principalClaim":"principal","operations":["create","patch","get","list","submit_request","revise_request","cancel_request","apply_request"],"readableFields":["target","label"],"writableFields":["target","label"],
          "applyTargets":[{"entity":"target", "rowBoundaries":"unrestricted"}],
          "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"
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
          "package":{{"sourceRevision":"{SOURCE_REVISION}"}},
          "modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]
        }}"#
    )
    .into_bytes();
    PackageBuildRequest {
        from_package_digest: None,
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint:
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
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
            bytes: b"apiVersion: id.registrystack.org/formats/breg/journeys/v1\nkind: BRegJourneys\njourneys: []\n"
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
    let previous = compile_variant(Variant::MetadataOnlyBase);
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
        history: None,
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
        prior_package_digest: PRIOR_REVISION.to_owned(),
        prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
        plan_sha256: digest(&descriptor_bytes),
        sql_sha256: Vec::new(),
        assertion_sha256: Vec::new(),
        fixture_inventory: Vec::new(),
        postgres_major: 16,
        row_assertions: Vec::new(),
        final_schema_fingerprint: FINAL_FINGERPRINT.to_owned(),
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
    let previous = compile_variant(Variant::ReferenceTargetBase);
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
        history: None,
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
        prior_package_digest: PRIOR_REVISION.to_owned(),
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
    let previous = compile_variant(Variant::Base);
    let candidate = compile_variant(Variant::RequiredAndOptionalFields);
    let source = reviewed_source_with_canaries(&previous, &candidate);
    let candidate_source = source_for_variant(Variant::RequiredAndOptionalFields);
    prepare_package(build_request(
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
        history: None,
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
        prior_package_digest: PRIOR_REVISION.to_owned(),
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
) -> registry_breg::package::IntegrityInspectedPackage {
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
        .publish_to_directory(&package)
        .expect("package publishes");
    inspect_package_integrity(&package).expect("package inspects")
}

/// Republish the shared package envelope over a test-authored change, so the
/// refusal under test comes from the registry package check rather than from
/// the checksum file.
#[cfg(feature = "tooling")]
fn refresh_shared_package_envelope(root: &std::path::Path) {
    let revision_path = root.join(REVISION_FILE);
    let revision = revision_path.exists().then(|| {
        fs::read_to_string(&revision_path)
            .expect("shared package revision reads")
            .strip_suffix('\n')
            .expect("shared package revision has one trailing newline")
            .to_owned()
    });
    fs::remove_file(root.join(SUM_FILE)).expect("old shared package checksum file removes");
    if revision.is_some() {
        fs::remove_file(revision_path).expect("old shared package revision file removes");
    }
    write_sum_file(
        root,
        revision.as_deref(),
        &SharedPackageLimits::default(),
        "bregctl package",
    )
    .expect("test-authored shared package envelope republishes");
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
    let previous = compile_variant(Variant::Base);
    let mut source = source_for_variant(Variant::Base);
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

    let unchanged =
        compiled_registry_change_set(&previous, &compile_variant(Variant::Base), PRIOR_REVISION);
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

#[test]
fn lookup_grant_addition_uses_its_routed_authority_without_storage_ddl() {
    let fixture = include_bytes!("../../../products/breg/evidence/registry/registry.yaml");
    let mut source: serde_json::Value = serde_norway::from_slice(fixture).unwrap();
    source["entities"][0]
        .as_object_mut()
        .unwrap()
        .remove("selectorProfiles");
    source["accessProfiles"].as_array_mut().unwrap().truncate(1);
    let compile = |source: &serde_json::Value| {
        let project = parse_project_yaml(&serde_json::to_vec(source).unwrap()).unwrap();
        compile_project(&project, &[], CompileProfile::Production).unwrap()
    };
    let previous = compile(&source);
    source["entities"][0]["selectorProfiles"] =
        serde_json::json!([{"id":"by-code","fields":["code"]}]);
    source["accessProfiles"].as_array_mut().unwrap().push(serde_json::json!({
        "id":"source","principalClaim":"registry_principal","requiredScopes":["registry:source:lookup"],
        "permissions":[{"entity":"record","operations":["lookup"],"readableFields":["code","status"],
            "lookups":[{"selector":"by-code","valueOrigin":"request"}],"rowBoundaries":"unrestricted"}]}));
    let candidate = compile(&source);
    let changes = compiled_registry_change_set(&previous, &candidate, PRIOR_REVISION);
    let plan = change_set_to_applicable_migration_plan(&changes)
        .expect("lookup-only authority is a policy successor");
    assert!(plan.statements.is_empty());
    assert!(changes
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::QueryInventoryChanged));
    // Changing an existing query projection does not become a grant addition.
    source["accessProfiles"][1]["permissions"][0]["readableFields"] =
        serde_json::json!(["code", "status", "label"]);
    let widened = compile(&source);
    let changes = compiled_registry_change_set(&candidate, &widened, PRIOR_REVISION);
    assert!(change_set_to_applicable_migration_plan(&changes).is_err());
}

#[test]
fn cross_entity_read_path_grant_addition_and_removal_are_policy_successors() {
    let fixture = include_bytes!("../../../products/breg/evidence/registry/registry.yaml");
    let mut source: serde_json::Value = serde_norway::from_slice(fixture).unwrap();
    source["accessProfiles"].as_array_mut().unwrap().truncate(1);
    source["entities"][0]["readPaths"] = serde_json::json!([
        {"id":"children","through":"link","to":"child","route":"children"}
    ]);
    let dataset = source["entities"][0]["primaryDataset"].clone();
    source["entities"].as_array_mut().unwrap().extend([
        serde_json::json!({"id":"child","primaryDataset":dataset,"route":"children","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maxLength":64,"classification":"internal"},
                      {"id":"label","type":"string","maxLength":100,"classification":"internal"}]}),
        serde_json::json!({"id":"link","primaryDataset":dataset,"route":"links","mutationMode":"mutable",
            "fields":[{"id":"record","type":"reference","target":"record","classification":"internal"},
                      {"id":"child","type":"reference","target":"child","classification":"internal"}]})
    ]);
    source["accessProfiles"][0]["permissions"].as_array_mut().unwrap().extend([
        serde_json::json!({"entity":"child","operations":["get"],"readableFields":["code","label"],"rowBoundaries":"unrestricted"}),
        serde_json::json!({"entity":"link","operations":["get"],"readableFields":["record","child"],"rowBoundaries":"unrestricted"})
    ]);
    let compile = |source: &serde_json::Value| {
        let project = parse_project_yaml(&serde_json::to_vec(source).unwrap()).unwrap();
        compile_project(&project, &[], CompileProfile::Production).unwrap()
    };
    let previous = compile(&source);
    source["accessProfiles"][0]["permissions"][0]["readPaths"] =
        serde_json::json!([{"path":"children","readableFields":["code"]}]);
    let granted = compile(&source);
    let query = granted
        .queries()
        .operations
        .iter()
        .find(|query| query.read_path.as_deref() == Some("children"))
        .unwrap();
    let route = granted
        .routes()
        .routes
        .iter()
        .find(|route| route.id == query.route_id)
        .unwrap();
    assert_eq!(query.entity_id, "child");
    assert_eq!(route.entity_id, "record");
    assert!(!granted.entities()["record"].access_profiles["operator"]
        .operations
        .contains(&registry_breg::contract::Operation::List));
    let changes = compiled_registry_change_set(&previous, &granted, PRIOR_REVISION);
    let plan = change_set_to_applicable_migration_plan(&changes)
        .expect("adding a source read-path grant is a policy successor");
    assert!(plan.statements.is_empty());
    assert!(changes
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::QueryInventoryChanged));

    source["accessProfiles"][0]["permissions"][0]["readPaths"][0]["readableFields"] =
        serde_json::json!(["code", "label"]);
    let widened = compile(&source);
    let changes = compiled_registry_change_set(&granted, &widened, PRIOR_REVISION);
    assert!(
        change_set_to_applicable_migration_plan(&changes).is_err(),
        "an existing query projection change still requires review"
    );

    source["accessProfiles"][0]["permissions"][0]["readPaths"] = serde_json::json!([]);
    let removed = compile(&source);
    let changes = compiled_registry_change_set(&granted, &removed, PRIOR_REVISION);
    let plan = change_set_to_applicable_migration_plan(&changes)
        .expect("removing a source read-path grant is a policy successor");
    assert_eq!(plan.statements.len(), 3);
    assert!(plan.statements.iter().all(|statement| {
        statement.sql.starts_with("DROP POLICY ")
            && statement.sql.contains("registry_path_rls_select_")
    }));
    assert!(changes
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::QueryInventoryChanged));
}
