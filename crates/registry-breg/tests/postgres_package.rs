// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

#[path = "support/postgres_harness.rs"]
mod postgres_harness;

#[path = "postgres_package/fingerprint.rs"]
mod fingerprint_tests;

#[cfg(feature = "tooling")]
#[path = "postgres_package/policy_upgrade.rs"]
mod policy_upgrade_tests;

#[cfg(feature = "tooling")]
#[path = "postgres_package/derived_upgrade.rs"]
mod derived_upgrade_tests;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use postgres_harness::TestDatabase;
use registry_breg::compiler::{
    compile_project, module_digest, module_digest_with_assets, CompileProfile,
};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml, ModuleAssetSource};
use registry_breg::event_destination::EventDestinationCompatibilityInventory;
use registry_breg::migration::{
    apply_verified_package, plan_verified_package, read_recorded_registry_state,
    ActivationDeployment, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest, MigrationError, PlannedActivation,
};
#[cfg(feature = "tooling")]
use registry_breg::migration_plan::{
    MigrationRehearsalReceipt, ReviewedChangeCover, ReviewedMigrationDescriptor,
    ReviewedMigrationFile, ReviewedMigrationRecovery, ReviewedMigrationSource,
};
use registry_breg::package::{
    change_set_to_applicable_migration_plan, compiled_registry_change_set, load_package,
    load_package_with_verified_envelope, load_predecessor_package, prepare_package,
    CompiledRegistryChangeClass, CompiledRegistryChangeCode, PackageBuildRequest, PackageEnvelope,
    PackageError, PackageFile, PackageFileRole, PackageLoadContext, PackageManifest,
    PackageMigrationPlanInput, PackageModuleSource, PackageSourceFile,
    MAX_PACKAGE_SOURCE_FILE_BYTES,
};
use registry_breg::postgres::{
    begin_record_transaction, install_compiled_schema, managed_schema_fingerprint, ClaimContext,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, RegistryLockKey,
};
use registry_breg::runtime_config::parse_runtime_config;
use registry_breg::startup::{prepare_startup, StartupError};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::package::{
    verify_package as verify_shared_package, write_sum_file, PackageLimits as SharedPackageLimits,
    REVISION_FILE, SUM_FILE,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_postgres::GenericClient;
use uuid::Uuid;

const INSTANCE: &str = "instance-under-test";
const DATABASE: &str = "database-under-test";
const SOURCE_REVISION: &str = "compiler-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: package-read
    steps:
      - id: list-neutral-records
        entity: neutral-record
        accessProfile: reader
        claims: {principal: package-reader}
        request: {type: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn package_builder_is_deterministic_and_local_publication_loads() {
    let module_bytes = module_bytes(PlanChoice::Schema);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let project_bytes = project_bytes(&module_digest(&module));
    let request = build_request(BuildRequestParts {
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes,
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    });
    let first = prepare_package(request.clone()).expect("first package prepares");
    let second = prepare_package(request).expect("second package prepares");
    assert_eq!(first.manifest(), second.manifest());
    assert_eq!(
        first.package_digest().unwrap(),
        second.package_digest().unwrap()
    );
    assert_eq!(first.file_bytes(), second.file_bytes());
    assert_eq!(first.registry(), second.registry());

    let root = TempRoot::create();
    let first_shared = first
        .publish_to_directory_with_revision(root.path(), Some("source-1"))
        .expect("local package publishes");
    let repeated_root = TempRoot::create();
    let repeated_shared = second
        .publish_to_directory_with_revision(repeated_root.path(), Some("source-1"))
        .expect("the same local package publishes again");
    assert_eq!(first_shared.digest(), repeated_shared.digest());
    assert_eq!(first_shared.revision(), Some("source-1"));
    assert_eq!(
        verify_shared_package(
            root.path(),
            &SharedPackageLimits::default(),
            "bregctl package"
        )
        .expect("shared package verifies")
        .digest(),
        first_shared.digest()
    );
    let replacement_root = TempRoot::create();
    second
        .publish_to_directory_with_revision(replacement_root.path(), Some("source-2"))
        .expect("same signed package publishes with different operator revision");
    assert!(matches!(
        load_package_with_verified_envelope(
            replacement_root.path(),
            &local_context(),
            &first_shared,
        ),
        Err(PackageError::Envelope)
    ));
    load_package(root.path(), &local_context()).expect("published local package loads");
    assert_eq!(
        first
            .publish_to_directory(root.path())
            .expect_err("package publication refuses replacement"),
        PackageError::Closure
    );
}

#[test]
fn package_builder_refuses_successor_without_prior_compiled_registry() {
    let module_bytes = module_bytes(PlanChoice::SecondTable);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let project_bytes = project_bytes(&module_digest(&module));
    let refused = prepare_package(build_request(BuildRequestParts {
        prior_revision: Some(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        ),
        schema_fingerprint: fingerprint(1),
        project_bytes,
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    }));
    assert_eq!(refused.err(), Some(PackageError::MigrationPlan));
}

#[test]
fn package_layout_contract_conditional_manifest_projection_is_in_projected_closure() {
    let layout = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/breg/contracts/package-layout.yaml"
    ))
    .expect("package layout contract reads");
    assert!(
        layout.contains("path: manifest/registry-manifest.json, role: lossy-manifest-projection, required: false"),
        "package-layout.yaml makes the lossy manifest projection conditional"
    );
    assert!(
        layout
            .contains("path: manifest/dcat.jsonld, role: dcat-catalog-projection, required: false"),
        "package-layout.yaml makes the DCAT catalog projection conditional"
    );

    let module_bytes = module_bytes(PlanChoice::Schema);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let project_bytes = project_bytes(&module_digest(&module));
    let package = prepare_package(build_request(BuildRequestParts {
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes,
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    }))
    .expect("maximal coherent package prepares");
    assert!(package
        .manifest()
        .files
        .iter()
        .any(|entry| entry.path == "manifest/registry-manifest.json"
            && entry.role == PackageFileRole::LossyManifestProjection));
    assert!(package
        .file_bytes()
        .contains_key("manifest/registry-manifest.json"));
    assert!(package.manifest().files.iter().any(|entry| {
        entry.path == "manifest/dcat.jsonld" && entry.role == PackageFileRole::DcatCatalogProjection
    }));
    assert!(package.file_bytes().contains_key("manifest/dcat.jsonld"));
    assert!(package
        .manifest()
        .files
        .iter()
        .any(|entry| entry.path == "inventories/events.json"
            && entry.role == PackageFileRole::EventInventory));
    assert!(package.file_bytes().contains_key("inventories/events.json"));
    assert!(layout.contains("metadata/registry.json") && layout.contains("caller-safe-metadata"));
    assert!(layout.contains("tests/journeys.yaml") && layout.contains("fixture-journeys"));
    assert!(package
        .manifest()
        .files
        .iter()
        .any(|entry| entry.path == "metadata/registry.json"
            && entry.role == PackageFileRole::CallerSafeMetadata));
    assert!(package
        .manifest()
        .files
        .iter()
        .any(|entry| entry.path == "tests/journeys.yaml"
            && entry.role == PackageFileRole::FixtureJourneys));
    assert_eq!(
        package
            .file_bytes()
            .get("tests/journeys.yaml")
            .map(Vec::as_slice),
        Some(FIXTURE_JOURNEYS)
    );
    let exact_paths = package
        .file_bytes()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        exact_paths,
        BTreeSet::from([
            "database/ddl.sql",
            "database/migration-plan.json",
            "effective-model.json",
            "inventories/access.json",
            "inventories/events.json",
            "inventories/physical-names.json",
            "inventories/queries.json",
            "inventories/routes.json",
            "manifest/dcat.jsonld",
            "manifest/registry-manifest.json",
            "metadata/registry.json",
            "openapi/openapi.json",
            "schemas/neutral-record.schema.json",
            "source/modules/core/module.yaml",
            "source/registry.yaml",
            "tests/journeys.yaml",
        ])
    );
}

#[test]
fn projection_free_package_omits_manifest_projection_from_signed_closure_and_loads() {
    let module_bytes = module_bytes(PlanChoice::Schema);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let project_bytes = project_bytes_without_manifest(&module_digest(&module));
    let request = build_request(BuildRequestParts {
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes,
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    });

    let first = prepare_package(request.clone()).expect("projection-free package prepares");
    let second = prepare_package(request).expect("projection-free package prepares again");
    assert_eq!(first.manifest(), second.manifest());
    assert_eq!(
        first.package_digest().unwrap(),
        second.package_digest().unwrap()
    );
    assert_eq!(first.file_bytes(), second.file_bytes());
    assert!(first.registry().manifest_projection().is_none());
    assert!(first.manifest().files.iter().all(|entry| !matches!(
        entry.role,
        PackageFileRole::LossyManifestProjection | PackageFileRole::DcatCatalogProjection
    )));
    assert!(!first
        .file_bytes()
        .contains_key("manifest/registry-manifest.json"));
    assert!(!first.file_bytes().contains_key("manifest/dcat.jsonld"));

    let exact_paths = first
        .file_bytes()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        exact_paths,
        BTreeSet::from([
            "database/ddl.sql",
            "database/migration-plan.json",
            "effective-model.json",
            "inventories/access.json",
            "inventories/events.json",
            "inventories/physical-names.json",
            "inventories/queries.json",
            "inventories/routes.json",
            "metadata/registry.json",
            "openapi/openapi.json",
            "schemas/neutral-record.schema.json",
            "source/modules/core/module.yaml",
            "source/registry.yaml",
            "tests/journeys.yaml",
        ])
    );

    let root = TempRoot::create();
    first
        .publish_to_directory(root.path())
        .expect("projection-free package publishes");
    let loaded = load_package(root.path(), &local_context())
        .expect("projection-free package loads through full closure rederivation");
    assert!(loaded.registry().manifest_projection().is_none());
}

#[test]
fn projection_free_package_refuses_claimed_manifest_artifacts() {
    let module_bytes = module_bytes(PlanChoice::Schema);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let package = prepare_package(build_request(BuildRequestParts {
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes: project_bytes_without_manifest(&module_digest(&module)),
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    }))
    .expect("projection-free package prepares");
    let root = TempRoot::create();
    package
        .publish_to_directory(root.path())
        .expect("projection-free package publishes");

    let registry_manifest = br#"{"schema_version":"registry-manifest/v1"}"#;
    let dcat = br#"{"@context":"https://www.w3.org/ns/dcat.jsonld"}"#;
    let manifest_dir = root.path().join("manifest");
    fs::create_dir(&manifest_dir).expect("manifest directory creates");
    fs::write(
        manifest_dir.join("registry-manifest.json"),
        registry_manifest,
    )
    .expect("claimed manifest writes");
    fs::write(manifest_dir.join("dcat.jsonld"), dcat).expect("claimed DCAT writes");
    rewrite_unsigned(root.path(), |manifest| {
        manifest.files.extend([
            PackageFile {
                path: "manifest/registry-manifest.json".to_owned(),
                role: PackageFileRole::LossyManifestProjection,
                size: registry_manifest.len() as u64,
                sha256: format!("sha256:{}", hex(&Sha256::digest(registry_manifest))),
            },
            PackageFile {
                path: "manifest/dcat.jsonld".to_owned(),
                role: PackageFileRole::DcatCatalogProjection,
                size: dcat.len() as u64,
                sha256: format!("sha256:{}", hex(&Sha256::digest(dcat))),
            },
        ]);
        manifest
            .files
            .sort_by(|left, right| left.path.cmp(&right.path));
    });

    assert_eq!(
        load_error(root.path(), &local_context(),),
        PackageError::Derivation
    );
}

#[test]
fn fixture_journeys_are_required_at_the_fixed_path_and_change_the_package_revision() {
    let module_bytes = module_bytes(PlanChoice::Schema);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let project_bytes = project_bytes(&module_digest(&module));
    let request = build_request(BuildRequestParts {
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes,
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    });

    let mut wrong_path = request.clone();
    wrong_path.fixture_journeys.path = "source/journeys.yaml".to_owned();
    assert_eq!(
        prepare_package(wrong_path).err(),
        Some(PackageError::Closure)
    );
    let mut missing = request.clone();
    missing.fixture_journeys.bytes.clear();
    assert_eq!(prepare_package(missing).err(), Some(PackageError::Closure));
    let mut oversized = request.clone();
    oversized.fixture_journeys.bytes =
        vec![b'x'; usize::try_from(MAX_PACKAGE_SOURCE_FILE_BYTES).unwrap() + 1];
    assert_eq!(
        prepare_package(oversized).err(),
        Some(PackageError::Closure)
    );

    let first = prepare_package(request.clone()).expect("first journey closure prepares");
    let mut changed = request;
    changed.fixture_journeys.bytes.extend_from_slice(b"\n");
    let second = prepare_package(changed).expect("changed journey closure prepares");
    assert_ne!(
        first.package_digest().unwrap(),
        second.package_digest().unwrap()
    );
    assert_eq!(first.registry(), second.registry());
}

#[test]
fn derived_sql_assets_are_captured_and_bound_to_revisions() {
    let first = derived_asset_request(
        b"SELECT r.id AS id, r.code AS summary FROM registry_source.neutral_record r",
    );
    let second = derived_asset_request(
        b"SELECT r.id AS id, (r.code) AS summary FROM registry_source.neutral_record r",
    );
    let first = prepare_package(first).expect("first derived package prepares");
    let second = prepare_package(second).expect("second derived package prepares");

    assert!(first
        .file_bytes()
        .contains_key("source/modules/core/sql/summary.sql"));
    assert!(first.manifest().files.iter().any(|entry| {
        entry.path == "source/modules/core/sql/summary.sql"
            && entry.role == PackageFileRole::SourceModuleAsset
    }));
    assert_eq!(
        first.manifest().sources.modules[0].assets,
        vec!["sql/summary.sql".to_owned()]
    );
    assert_ne!(
        first.registry().module_closure(),
        second.registry().module_closure()
    );
    assert_ne!(first.registry().revision(), second.registry().revision());
    assert_ne!(
        first.package_digest().unwrap(),
        second.package_digest().unwrap()
    );
}

#[test]
fn derived_sql_asset_tampering_is_refused_before_activation() {
    let prepared = prepare_package(derived_asset_request(
        b"SELECT r.id AS id, r.code AS summary FROM registry_source.neutral_record r",
    ))
    .expect("derived package prepares");
    let root = TempRoot::create();
    prepared
        .publish_to_directory(root.path())
        .expect("package publishes");
    let context = local_context();
    load_package(root.path(), &context).expect("untampered asset package loads");

    let asset_path = root.path().join("source/modules/core/sql/summary.sql");
    let original = fs::read(&asset_path).expect("asset reads");
    fs::write(
        &asset_path,
        b"SELECT r.id AS id, (r.code) AS summary FROM registry_source.neutral_record r",
    )
    .expect("asset tamper writes");
    refresh_shared_package_envelope(root.path());
    assert_eq!(load_error(root.path(), &context), PackageError::Integrity);
    fs::write(&asset_path, original).expect("asset restores");
    refresh_shared_package_envelope(root.path());

    fs::remove_file(&asset_path).expect("asset removes");
    assert_eq!(load_error(root.path(), &context), PackageError::Envelope);
}

#[test]
fn derived_sql_asset_extra_path_swap_and_size_are_refused() {
    let prepared = prepare_package(derived_asset_request(
        b"SELECT r.id AS id, r.code AS summary FROM registry_source.neutral_record r",
    ))
    .expect("derived package prepares");
    let root = TempRoot::create();
    prepared
        .publish_to_directory(root.path())
        .expect("package publishes");
    let context = local_context();

    fs::write(
        root.path().join("source/modules/core/sql/unlisted.sql"),
        b"SELECT r.id AS id, r.code AS summary FROM registry_source.neutral_record r",
    )
    .expect("extra asset writes");
    refresh_shared_package_envelope(root.path());
    assert_eq!(load_error(root.path(), &context), PackageError::Envelope);
    fs::remove_file(root.path().join("source/modules/core/sql/unlisted.sql"))
        .expect("extra asset removes");
    refresh_shared_package_envelope(root.path());

    let original_path = root.path().join("source/modules/core/sql/summary.sql");
    let swapped_path = root.path().join("source/modules/core/sql/swapped.sql");
    fs::rename(&original_path, &swapped_path).expect("asset path swaps");
    rewrite_unsigned(root.path(), |manifest| {
        manifest.sources.modules[0].assets = vec!["sql/swapped.sql".to_owned()];
        let entry = manifest
            .files
            .iter_mut()
            .find(|entry| entry.path == "source/modules/core/sql/summary.sql")
            .expect("asset entry exists");
        entry.path = "source/modules/core/sql/swapped.sql".to_owned();
    });
    assert_eq!(load_error(root.path(), &context), PackageError::Derivation);

    let mut oversized = derived_asset_request(
        b"SELECT r.id AS id, r.code AS summary FROM registry_source.neutral_record r",
    );
    let bytes = vec![b'x'; 256 * 1024 + 1];
    let module = parse_module_yaml(&oversized.modules[0].bytes).expect("module parses");
    oversized.modules[0].assets[0].bytes = bytes.clone();
    oversized.project.bytes = project_bytes(&module_digest_with_assets(
        &module,
        &[ModuleAssetSource {
            module: Some("core".to_owned()),
            path: "sql/summary.sql".to_owned(),
            bytes,
        }],
    ));
    assert_eq!(
        prepare_package(oversized).err(),
        Some(PackageError::Derivation)
    );
}

#[test]
fn package_refuses_missing_fixture_journeys_and_a_rehashed_substitution_is_another_package() {
    let missing = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    fs::remove_file(missing.root.path().join("tests/journeys.yaml"))
        .expect("fixture journeys remove");
    assert_eq!(
        load_error(missing.root.path(), &missing.context()),
        PackageError::Envelope
    );

    // A package carries no signature, so a consistently rehashed substitution
    // loads, but as a different package: its digest is not the one the
    // database ledger records for the original.
    let substituted = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let original_digest = substituted.digest();
    let replacement = [FIXTURE_JOURNEYS, b"\n"].concat();
    fs::write(
        substituted.root.path().join("tests/journeys.yaml"),
        &replacement,
    )
    .expect("fixture journeys substitution writes");
    rewrite_envelope(substituted.root.path(), |envelope| {
        let entry = envelope
            .manifest
            .files
            .iter_mut()
            .find(|entry| entry.role == PackageFileRole::FixtureJourneys)
            .expect("fixture journey entry exists");
        entry.size = replacement.len() as u64;
        entry.sha256 = format!("sha256:{}", hex(&Sha256::digest(&replacement)));
    });
    let loaded = load_package(substituted.root.path(), &substituted.context())
        .expect("a consistently rehashed package loads as itself");
    assert_ne!(loaded.package_digest(), original_digest);
}

#[test]
fn package_rederivation_refuses_a_rehashed_fixture_journey_role_substitution() {
    let fixture = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    rewrite_unsigned(fixture.root.path(), |manifest| {
        manifest
            .files
            .iter_mut()
            .find(|entry| entry.path == "tests/journeys.yaml")
            .expect("fixture journey entry exists")
            .role = PackageFileRole::SourceModule;
    });

    assert_eq!(
        load_error(fixture.root.path(), &local_context(),),
        PackageError::Derivation
    );
}

#[test]
fn package_rederivation_refuses_rehashed_empty_fixture_journeys() {
    let fixture = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    fs::write(fixture.root.path().join("tests/journeys.yaml"), b"")
        .expect("empty fixture journeys write");
    rewrite_unsigned(fixture.root.path(), |manifest| {
        let entry = manifest
            .files
            .iter_mut()
            .find(|entry| entry.role == PackageFileRole::FixtureJourneys)
            .expect("fixture journey entry exists");
        entry.size = 0;
        entry.sha256 = format!("sha256:{}", hex(&Sha256::digest(b"")));
    });

    assert_eq!(
        load_error(fixture.root.path(), &local_context(),),
        PackageError::Derivation
    );
}

#[test]
fn package_rederivation_refuses_rehashed_substituted_caller_safe_metadata() {
    let fixture = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let path = fixture.root.path().join("metadata/registry.json");
    let substituted = br#"{"entities":[],"registryId":"neutral-registry","version":"1"}"#;
    fs::write(&path, substituted).expect("caller-safe metadata substitution writes");
    rewrite_unsigned(fixture.root.path(), |manifest| {
        let entry = manifest
            .files
            .iter_mut()
            .find(|entry| entry.role == PackageFileRole::CallerSafeMetadata)
            .expect("caller-safe metadata entry exists");
        entry.size = substituted.len() as u64;
        entry.sha256 = format!("sha256:{}", hex(&Sha256::digest(substituted)));
    });

    assert_eq!(
        load_error(fixture.root.path(), &local_context(),),
        PackageError::Derivation
    );
}

#[test]
fn package_rederivation_refuses_a_rehashed_substituted_event_inventory() {
    let fixture = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let path = fixture.root.path().join("inventories/events.json");
    let substituted = br#"{"deliveries":[{"canary":"not-compiled"}]}"#;
    fs::write(&path, substituted).expect("event inventory substitution writes");
    rewrite_unsigned(fixture.root.path(), |manifest| {
        let entry = manifest
            .files
            .iter_mut()
            .find(|entry| entry.role == PackageFileRole::EventInventory)
            .expect("event inventory entry exists");
        entry.size = substituted.len() as u64;
        entry.sha256 = format!("sha256:{}", hex(&Sha256::digest(substituted)));
    });

    assert_eq!(
        load_error(fixture.root.path(), &local_context(),),
        PackageError::Derivation
    );
}

#[test]
fn local_unsigned_package_rederives_every_artifact_and_refuses_filesystem_tampering() {
    let fixture = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let context = local_context();
    let verified =
        load_package(fixture.root.path(), &context).expect("local unsigned package verifies");
    assert_eq!(verified.manifest().package_id, "neutral-registry");
    assert_eq!(verified.registry().registry_id(), "neutral-registry");

    let artifact_path = first_generated_path(fixture.root.path());
    let original = fs::read(&artifact_path).expect("artifact reads");
    fs::write(&artifact_path, b"tampered artifact").expect("artifact tamper writes");
    refresh_shared_package_envelope(fixture.root.path());
    assert_eq!(
        load_error(fixture.root.path(), &context),
        PackageError::Integrity
    );
    fs::write(&artifact_path, original).expect("artifact restores");
    refresh_shared_package_envelope(fixture.root.path());

    let manifest_projection_path = manifest_projection_path(fixture.root.path());
    let original_manifest_projection_bytes =
        fs::read(&manifest_projection_path).expect("Manifest projection reads");
    let original_manifest_projection_entry = read_envelope(fixture.root.path())
        .manifest
        .files
        .iter()
        .find(|entry| entry.role == PackageFileRole::LossyManifestProjection)
        .expect("original Manifest projection entry exists")
        .clone();
    let tampered_manifest = br#"{"schema_version":"registry-manifest/v1","catalog":{"id":"neutral-registry","base_url":"https://package.example.test","title":"Tampered","publisher":{"name":"Publisher"}},"datasets":[],"codelists":[]}"#;
    fs::write(&manifest_projection_path, tampered_manifest)
        .expect("Manifest projection tamper writes");
    rewrite_unsigned(fixture.root.path(), |manifest| {
        let entry = manifest
            .files
            .iter_mut()
            .find(|entry| entry.role == PackageFileRole::LossyManifestProjection)
            .expect("manifest projection entry exists");
        entry.size = tampered_manifest.len() as u64;
        entry.sha256 = format!("sha256:{}", hex(&Sha256::digest(tampered_manifest)));
    });
    assert_eq!(
        load_error(fixture.root.path(), &context),
        PackageError::Derivation
    );
    fs::write(
        &manifest_projection_path,
        original_manifest_projection_bytes,
    )
    .expect("Manifest projection restores");
    rewrite_unsigned(fixture.root.path(), |manifest| {
        let entry = manifest
            .files
            .iter_mut()
            .find(|entry| entry.role == PackageFileRole::LossyManifestProjection)
            .expect("manifest projection entry exists");
        entry.size = original_manifest_projection_entry.size;
        entry
            .sha256
            .clone_from(&original_manifest_projection_entry.sha256);
    });

    let source = fixture.root.path().join("source/registry.yaml");
    let original = fs::read(&source).expect("source reads");
    fs::write(&source, b"tampered source").expect("source tamper writes");
    refresh_shared_package_envelope(fixture.root.path());
    assert_eq!(
        load_error(fixture.root.path(), &context),
        PackageError::Integrity
    );
    fs::write(&source, original).expect("source restores");
    refresh_shared_package_envelope(fixture.root.path());

    let module = fixture.root.path().join("source/modules/core/module.yaml");
    let original = fs::read(&module).expect("module reads");
    fs::write(&module, b"tampered module").expect("module tamper writes");
    refresh_shared_package_envelope(fixture.root.path());
    assert_eq!(
        load_error(fixture.root.path(), &context),
        PackageError::Integrity
    );
    fs::write(&module, original).expect("module restores");
    refresh_shared_package_envelope(fixture.root.path());

    fs::write(fixture.root.path().join("unlisted"), b"unlisted").expect("unlisted file writes");
    refresh_shared_package_envelope(fixture.root.path());
    assert_eq!(
        load_error(fixture.root.path(), &context),
        PackageError::Envelope
    );
    fs::remove_file(fixture.root.path().join("unlisted")).expect("unlisted file removes");
    refresh_shared_package_envelope(fixture.root.path());

    fs::remove_file(&artifact_path).expect("listed artifact removes");
    assert_eq!(
        load_error(fixture.root.path(), &context),
        PackageError::Envelope
    );
}

#[test]
fn package_manifest_refuses_ddl_checksum_path_and_canonical_json_tampering() {
    let context = local_context();

    let ddl = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    rewrite_unsigned(ddl.root.path(), |manifest| {
        manifest.migration_plan.statements[0]
            .sql
            .push_str(" SELECT 1");
    });
    assert_eq!(
        load_error(ddl.root.path(), &context),
        PackageError::MigrationPlan
    );

    let checksum = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    rewrite_unsigned(checksum.root.path(), |manifest| {
        manifest.files[0].sha256 = fingerprint(9);
    });
    assert_eq!(
        load_error(checksum.root.path(), &context),
        PackageError::Integrity
    );

    let duplicate = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    rewrite_unsigned(duplicate.root.path(), |manifest| {
        manifest.files.insert(0, manifest.files[0].clone());
    });
    assert_eq!(
        load_error(duplicate.root.path(), &context),
        PackageError::Closure
    );

    let traversal = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    rewrite_unsigned(traversal.root.path(), |manifest| {
        manifest.files[0].path = "../outside".to_owned();
    });
    assert_eq!(
        load_error(traversal.root.path(), &context),
        PackageError::UnsafePath
    );

    let absolute = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    rewrite_unsigned(absolute.root.path(), |manifest| {
        manifest.files[0].path = "/absolute".to_owned();
    });
    assert_eq!(
        load_error(absolute.root.path(), &context),
        PackageError::UnsafePath
    );

    let noncanonical_path = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    rewrite_unsigned(noncanonical_path.root.path(), |manifest| {
        manifest.files[0].path = "source//registry.yaml".to_owned();
    });
    assert_eq!(
        load_error(noncanonical_path.root.path(), &context),
        PackageError::UnsafePath
    );

    let nonregular = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let path = first_generated_path(nonregular.root.path());
    fs::remove_file(&path).expect("listed file removes");
    fs::create_dir(&path).expect("non-regular replacement creates");
    assert_eq!(
        load_error(nonregular.root.path(), &context),
        PackageError::Envelope
    );

    let noncanonical = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let path = noncanonical.root.path().join("package.json");
    let mut bytes = fs::read(&path).expect("manifest reads");
    bytes.push(b'\n');
    fs::write(&path, bytes).expect("noncanonical manifest writes");
    refresh_shared_package_envelope(noncanonical.root.path());
    assert_eq!(
        load_error(noncanonical.root.path(), &context),
        PackageError::CanonicalJson
    );
}

#[test]
fn successor_migration_plan_rederivation_rejects_tampered_closure() {
    let first = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let prior_revision = first.digest();
    let context = local_context();
    let build_successor = || {
        PackageFixture::build(
            Some(&prior_revision),
            fingerprint(1),
            PlanChoice::SecondTable,
        )
    };

    let valid = build_successor();
    let valid_package =
        load_package(valid.root.path(), &context).expect("untampered successor package loads");
    assert!(valid_package.manifest().migration_plan.statements.len() > 1);
    assert_eq!(
        valid_package
            .manifest()
            .migration_plan
            .prior_baseline
            .as_ref()
            .map(|baseline| baseline.package_digest.as_str()),
        Some(prior_revision.as_str())
    );

    let omitted = build_successor();
    rewrite_unsigned(omitted.root.path(), |manifest| {
        manifest.migration_plan.statements.pop();
    });
    assert_eq!(
        load_error(omitted.root.path(), &context),
        PackageError::MigrationPlan
    );

    let forged_baseline = build_successor();
    rewrite_unsigned(forged_baseline.root.path(), |manifest| {
        manifest
            .migration_plan
            .prior_baseline
            .as_mut()
            .expect("successor carries prior baseline")
            .package_digest = fingerprint(9);
    });
    assert_eq!(
        load_error(forged_baseline.root.path(), &context),
        PackageError::MigrationPlan
    );

    let forged_changes = build_successor();
    rewrite_unsigned(forged_changes.root.path(), |manifest| {
        manifest.migration_plan.changes.clear();
    });
    assert_eq!(
        load_error(forged_changes.root.path(), &context),
        PackageError::MigrationPlan
    );

    let reordered = build_successor();
    rewrite_unsigned(reordered.root.path(), |manifest| {
        manifest.migration_plan.statements.swap(0, 1);
    });
    assert_eq!(
        load_error(reordered.root.path(), &context),
        PackageError::MigrationPlan
    );

    let extra = build_successor();
    rewrite_unsigned(extra.root.path(), |manifest| {
        let extra = manifest.migration_plan.statements[0].clone();
        manifest.migration_plan.statements.push(extra);
    });
    assert_eq!(
        load_error(extra.root.path(), &context),
        PackageError::MigrationPlan
    );
}

#[cfg(unix)]
#[test]
fn package_refuses_symlinks_and_production_writable_permissions() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let local = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let artifact = first_generated_path(local.root.path());
    let target = local.root.path().join("ordinary-target");
    fs::write(&target, fs::read(&artifact).expect("artifact reads")).expect("target writes");
    fs::remove_file(&artifact).expect("artifact removes");
    symlink(&target, &artifact).expect("test symlink creates");
    let context = local_context();
    assert_eq!(
        load_error(local.root.path(), &context),
        PackageError::UnsafePath
    );

    let production = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    fs::set_permissions(production.root.path(), fs::Permissions::from_mode(0o777))
        .expect("test permissions change");
    let context = production.context();
    assert_eq!(
        load_error(production.root.path(), &context),
        PackageError::Permissions
    );
}

#[test]
fn predecessor_package_reports_the_digest_the_database_ledger_is_compared_with() {
    let fixture = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let revision = fixture.digest();
    let predecessor = load_predecessor_package(fixture.root.path(), &local_context())
        .expect("active predecessor package verifies");

    assert_eq!(predecessor.package_id(), "neutral-registry");
    assert_eq!(predecessor.package_digest(), revision);
    assert_eq!(predecessor.schema_fingerprint(), fingerprint(1));
    assert_eq!(predecessor.migration_baseline().package_digest, revision);
    assert_eq!(
        predecessor.migration_baseline().registry_id,
        "neutral-registry"
    );
}

#[test]
fn predecessor_package_refuses_altered_or_forged_closure_bytes() {
    let altered = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let context = local_context();
    let model_path = governed_model_path(altered.root.path());
    let original = fs::read(&model_path).expect("governed model reads");

    fs::write(&model_path, b"tampered governed model").expect("governed model tamper writes");
    refresh_shared_package_envelope(altered.root.path());
    assert_eq!(
        predecessor_load_error(altered.root.path(), &context),
        PackageError::Integrity
    );
    fs::write(&model_path, original).expect("governed model restores");
    refresh_shared_package_envelope(altered.root.path());

    let forged = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let active_revision = forged.digest();
    let model_path = governed_model_path(forged.root.path());
    let forged_bytes = fs::read(&model_path)
        .expect("governed model reads")
        .into_iter()
        .map(|byte| if byte == b'1' { b'2' } else { byte })
        .collect::<Vec<_>>();
    fs::write(&model_path, &forged_bytes).expect("forged governed model writes");
    rewrite_unsigned(forged.root.path(), |manifest| {
        let entry = manifest
            .files
            .iter_mut()
            .find(|entry| entry.role == PackageFileRole::GovernedModel)
            .expect("governed model entry exists");
        entry.size = forged_bytes.len() as u64;
        entry.sha256 = format!("sha256:{}", hex(&Sha256::digest(&forged_bytes)));
    });
    // A consistently rehashed forgery of the governed model is refused: the
    // running compiler does not derive it from the packaged sources, so it is
    // never mistaken for the active package the caller compares it with.
    assert_ne!(forged.digest(), active_revision);
    assert_eq!(
        predecessor_load_error(forged.root.path(), &context),
        PackageError::Derivation
    );
}

#[test]
fn package_without_the_shared_envelope_is_refused_by_every_reader() {
    let fixture = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    strip_shared_package_envelope(fixture.root.path());

    assert_eq!(
        load_error(fixture.root.path(), &local_context()),
        PackageError::Envelope
    );
    assert_eq!(
        predecessor_load_error(fixture.root.path(), &local_context()),
        PackageError::Envelope
    );
    assert_eq!(
        registry_breg::package::inspect_package_integrity(fixture.root.path())
            .err()
            .expect("integrity inspection refuses a package without SHA256SUMS"),
        PackageError::Envelope
    );
}

#[test]
fn predecessor_verification_does_not_weaken_successor_plan_checks() {
    let legacy_revision = "legacy-compiler-source-revision";
    let legacy = legacy_compiler_fixture(legacy_revision);
    let active_revision = legacy.digest();
    load_predecessor_package(legacy.root.path(), &local_context())
        .expect("legacy active predecessor verifies for planning");

    let successor = PackageFixture::build(
        Some(&active_revision),
        fingerprint(2),
        PlanChoice::SecondTable,
    );
    rewrite_unsigned(successor.root.path(), |manifest| {
        manifest.migration_plan.changes.clear();
    });
    let activation_context = local_context();
    assert_eq!(
        load_error(successor.root.path(), &activation_context),
        PackageError::MigrationPlan
    );
}

#[test]
fn policy_only_snapshot_grant_addition_prepares_and_loads_successor_without_reviewed_migration() {
    assert_policy_only_snapshot_grant_delta_prepares_and_loads(false, true);
}

#[test]
fn policy_only_snapshot_grant_removal_prepares_and_loads_successor_without_reviewed_migration() {
    assert_policy_only_snapshot_grant_delta_prepares_and_loads(true, false);
}

#[test]
fn query_shape_rewrite_with_additive_field_requires_reviewed_migration() {
    let baseline_module_bytes = temporal_policy_module_bytes(true);
    let baseline_module =
        parse_module_yaml(&baseline_module_bytes).expect("baseline module parses");
    let baseline = prepare_package(build_request(BuildRequestParts {
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes: project_bytes(&module_digest(&baseline_module)),
        module_bytes: baseline_module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    }))
    .expect("baseline package prepares");
    let active_revision = baseline.package_digest().unwrap().to_owned();

    let successor_module_bytes = temporal_policy_module_bytes_with(
        true,
        r#",{"id":"review-note","type":"string","maxLength":120,"classification":"internal"}"#,
        r#", "allowCount": true"#,
    );
    let successor_module =
        parse_module_yaml(&successor_module_bytes).expect("successor module parses");
    let successor_project_bytes = project_bytes(&module_digest(&successor_module));
    let successor_registry = compile_project(
        &parse_project_yaml(&successor_project_bytes).expect("successor project parses"),
        std::slice::from_ref(&successor_module),
        CompileProfile::Production,
    )
    .expect("successor compiles");
    let change_set =
        compiled_registry_change_set(baseline.registry(), &successor_registry, &active_revision);
    assert!(change_set.changes.iter().any(|change| {
        change.code == CompiledRegistryChangeCode::QueryInventoryChanged
            && change.class == CompiledRegistryChangeClass::AccessOrDisclosureChange
    }));
    assert!(change_set_to_applicable_migration_plan(&change_set).is_err());
    let refused = prepare_package(build_request(BuildRequestParts {
        prior_revision: Some(&active_revision),
        schema_fingerprint: fingerprint(2),
        project_bytes: successor_project_bytes,
        module_bytes: successor_module_bytes,
        migration_plan: PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(baseline.registry().clone()),
        },
    }));

    assert_eq!(refused.err(), Some(PackageError::MigrationPlan));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_only_snapshot_grant_add_and_remove_apply_without_ddl() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs prerequisite");
    let (mut migration, migration_task) = database.connect_migration().await;

    let first = publish_temporal_policy_package(
        None,
        fingerprint(1),
        temporal_policy_module_bytes(false),
        PackageMigrationPlanInput::InitialCompiledDdl,
    );
    let provisional_first = load_package(first.path(), &local_context())
        .expect("initial temporal policy package verifies before fingerprinting");
    let transaction = migration
        .transaction()
        .await
        .expect("initial temporal policy fingerprint transaction starts");
    install_compiled_schema(
        &transaction,
        provisional_first.registry(),
        &database.runtime_role,
    )
    .await
    .expect("initial temporal policy schema installs for fingerprinting");
    let first_catalog = ExpectedManagedCatalog::compiled(provisional_first.registry());
    let first_fingerprint =
        managed_schema_fingerprint(&transaction, &database.runtime_role, &first_catalog)
            .await
            .expect("initial temporal policy fingerprint derives");
    transaction
        .rollback()
        .await
        .expect("initial temporal policy fingerprint transaction rolls back");
    rewrite_unsigned(first.path(), |manifest| {
        manifest.schema_fingerprint.clone_from(&first_fingerprint);
    });
    let verified_first = load_package(first.path(), &local_context())
        .expect("initial temporal policy package reloads with exact fingerprint");
    let active_first = apply_package(
        &database,
        &verified_first,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .expect("initial temporal policy package applies");

    let add_snapshot = publish_temporal_policy_package(
        Some(&active_first.package_digest),
        active_first.schema_fingerprint.clone(),
        temporal_policy_module_bytes(true),
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(verified_first.registry().clone()),
        },
    );
    let add_context = local_context();
    let verified_add =
        load_package(add_snapshot.path(), &add_context).expect("snapshot grant successor verifies");
    assert!(verified_add.manifest().migration_plan.statements.is_empty());
    let active_add = apply_package(
        &database,
        &verified_add,
        ApplyPrecondition::Successor {
            current: &active_first,
        },
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .expect("metadata-only snapshot grant applies");

    let remove_snapshot = publish_temporal_policy_package(
        Some(&active_add.package_digest),
        active_add.schema_fingerprint.clone(),
        temporal_policy_module_bytes(false),
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(verified_add.registry().clone()),
        },
    );
    let remove_context = local_context();
    let verified_remove = load_package(remove_snapshot.path(), &remove_context)
        .expect("snapshot revocation successor verifies");
    assert!(verified_remove
        .manifest()
        .migration_plan
        .statements
        .is_empty());
    let active_remove = apply_package(
        &database,
        &verified_remove,
        ApplyPrecondition::Successor {
            current: &active_add,
        },
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .expect("metadata-only snapshot revocation applies");
    assert_eq!(
        ledger_apply_order(&database, &active_remove.activation_id).await,
        3
    );
    assert_eq!(
        active_remove.schema_fingerprint,
        active_first.schema_fingerprint
    );

    migration_task.abort();
    database.cleanup().await;
}

#[cfg(feature = "tooling")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reviewed_metadata_only_query_access_change_applies_without_dummy_sql() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs prerequisite");
    let (mut migration, migration_task) = database.connect_migration().await;

    let hidden_note_field =
        r#",{"id":"review-note","type":"string","maxLength":120,"classification":"internal"}"#;
    let first = publish_temporal_policy_package(
        None,
        fingerprint(1),
        temporal_policy_module_bytes_with(true, hidden_note_field, ""),
        PackageMigrationPlanInput::InitialCompiledDdl,
    );
    let provisional_first = load_package(first.path(), &local_context())
        .expect("initial package verifies before fingerprinting");
    let transaction = migration
        .transaction()
        .await
        .expect("initial fingerprint transaction starts");
    install_compiled_schema(
        &transaction,
        provisional_first.registry(),
        &database.runtime_role,
    )
    .await
    .expect("initial schema installs for fingerprinting");
    let first_catalog = ExpectedManagedCatalog::compiled(provisional_first.registry());
    let first_fingerprint =
        managed_schema_fingerprint(&transaction, &database.runtime_role, &first_catalog)
            .await
            .expect("initial fingerprint derives");
    transaction
        .rollback()
        .await
        .expect("initial fingerprint transaction rolls back");
    rewrite_unsigned(first.path(), |manifest| {
        manifest.schema_fingerprint.clone_from(&first_fingerprint);
    });
    let verified_first = load_package(first.path(), &local_context())
        .expect("initial package reloads with exact fingerprint");
    let active_first = apply_package(
        &database,
        &verified_first,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .expect("initial package applies");

    let successor_module_bytes =
        String::from_utf8(temporal_policy_module_bytes_with(true, hidden_note_field, ""))
            .expect("module fixture is UTF-8")
            .replace(
                r#""readableFields":["person","valid-from","valid-to"],"filterableFields":["person","valid-from"]"#,
                r#""readableFields":["person","valid-from","valid-to","review-note"],"filterableFields":["person","valid-from","review-note"]"#,
            )
            .into_bytes();
    let successor_module =
        parse_module_yaml(&successor_module_bytes).expect("successor module parses");
    let successor_project_bytes = project_bytes(&module_digest(&successor_module));
    let successor_registry = compile_project(
        &parse_project_yaml(&successor_project_bytes).expect("successor project parses"),
        std::slice::from_ref(&successor_module),
        CompileProfile::Production,
    )
    .expect("successor compiles");
    let change_set = compiled_registry_change_set(
        verified_first.registry(),
        &successor_registry,
        &active_first.package_digest,
    );
    assert!(change_set_to_applicable_migration_plan(&change_set).is_err());
    assert!(change_set.changes.iter().any(|change| {
        change.code == CompiledRegistryChangeCode::QueryInventoryChanged
            && change.class == CompiledRegistryChangeClass::AccessOrDisclosureChange
    }));
    let review = metadata_only_review_source(
        &change_set.changes,
        &active_first.package_digest,
        &active_first.schema_fingerprint,
        &active_first.schema_fingerprint,
    );
    let successor = publish_temporal_policy_package(
        Some(&active_first.package_digest),
        active_first.schema_fingerprint.clone(),
        successor_module_bytes,
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(verified_first.registry().clone()),
            prior_schema_fingerprint: active_first.schema_fingerprint.clone(),
            migrations: vec![review],
        },
    );
    let successor_context = local_context();
    let verified_successor = load_package(successor.path(), &successor_context)
        .expect("reviewed metadata-only successor verifies");
    assert!(verified_successor
        .manifest()
        .migration_plan
        .statements
        .is_empty());
    let active_successor = apply_package(
        &database,
        &verified_successor,
        ApplyPrecondition::Successor {
            current: &active_first,
        },
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .expect("reviewed metadata-only successor applies without dummy SQL");
    assert_eq!(
        ledger_apply_order(&database, &active_successor.activation_id).await,
        2
    );
    assert_eq!(
        active_successor.schema_fingerprint,
        active_first.schema_fingerprint
    );

    migration_task.abort();
    database.cleanup().await;
}

fn assert_policy_only_snapshot_grant_delta_prepares_and_loads(
    baseline_snapshot: bool,
    successor_snapshot: bool,
) {
    let baseline_module_bytes = temporal_policy_module_bytes(baseline_snapshot);
    let baseline_module =
        parse_module_yaml(&baseline_module_bytes).expect("baseline module parses");
    let baseline = prepare_package(build_request(BuildRequestParts {
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes: project_bytes(&module_digest(&baseline_module)),
        module_bytes: baseline_module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    }))
    .expect("baseline package prepares");
    let active_revision = baseline.package_digest().unwrap().to_owned();

    let successor_module_bytes = temporal_policy_module_bytes(successor_snapshot);
    let successor_module =
        parse_module_yaml(&successor_module_bytes).expect("successor module parses");
    let successor = prepare_package(build_request(BuildRequestParts {
        prior_revision: Some(&active_revision),
        schema_fingerprint: fingerprint(2),
        project_bytes: project_bytes(&module_digest(&successor_module)),
        module_bytes: successor_module_bytes,
        migration_plan: PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(baseline.registry().clone()),
        },
    }))
    .expect("snapshot policy delta prepares without reviewed migration");

    assert!(successor
        .manifest()
        .migration_plan
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::QueryInventoryChanged));
    assert!(successor
        .manifest()
        .migration_plan
        .changes
        .iter()
        .all(|change| {
            matches!(
                change.class,
                CompiledRegistryChangeClass::CompatibleAdditive
                    | CompiledRegistryChangeClass::AccessOrDisclosureChange
            )
        }));
    assert!(successor.manifest().migration_plan.statements.is_empty());

    let root = TempRoot::create();
    successor
        .publish_to_directory(root.path())
        .expect("successor package publishes");
    load_package(root.path(), &local_context()).expect("policy-only successor strict-loads");
}

/// The control for the refusals below: rewriting the temporal metadata with
/// no change leaves a package the predecessor loader still accepts, so each
/// refusal is caused by the change it names and not by the rewrite.
#[test]
fn predecessor_package_loads_after_an_unchanged_temporal_rewrite() {
    let older = PackageFixture::build(None, fingerprint(1), PlanChoice::TemporalSchema);
    rewrite_temporal_metadata(older.root.path(), false, |_| {});
    load_predecessor_package(older.root.path(), &local_context())
        .expect("an unchanged temporal package loads as a predecessor");
}

#[test]
fn predecessor_package_refuses_a_temporal_value_kind_its_fields_do_not_have() {
    let older = PackageFixture::build(None, fingerprint(1), PlanChoice::TemporalSchema);
    rewrite_temporal_metadata(older.root.path(), false, |temporal| {
        let temporal = temporal
            .as_object_mut()
            .expect("temporal binding is an object");
        let other = match temporal["valueKind"]
            .as_str()
            .expect("temporal binding names a value kind")
        {
            "date" => "timestamp",
            "timestamp" => "date",
            kind => panic!("unexpected temporal value kind {kind}"),
        };
        temporal.insert("valueKind".to_owned(), Value::String(other.to_owned()));
    });
    assert_eq!(
        predecessor_load_error(older.root.path(), &local_context()),
        PackageError::Derivation
    );
}

#[test]
fn predecessor_package_refuses_temporal_bindings_without_a_value_kind() {
    let older = PackageFixture::build(None, fingerprint(1), PlanChoice::TemporalSchema);
    rewrite_temporal_metadata(older.root.path(), false, |temporal| {
        temporal
            .as_object_mut()
            .expect("temporal binding is an object")
            .remove("valueKind");
    });
    assert_eq!(
        predecessor_load_error(older.root.path(), &local_context()),
        PackageError::Derivation
    );
}

#[test]
fn predecessor_package_refuses_temporal_scope_fields() {
    let older = PackageFixture::build(None, fingerprint(1), PlanChoice::TemporalSchema);
    rewrite_temporal_metadata(older.root.path(), true, |_| {});
    assert_eq!(
        predecessor_load_error(older.root.path(), &local_context()),
        PackageError::Derivation
    );
}

#[test]
fn production_package_loads_without_signatures_or_a_trust_anchor() {
    let fixture = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let loaded = load_package(fixture.root.path(), &fixture.context())
        .expect("an unsigned package verifies under production strictness");
    assert_eq!(loaded.package_digest(), fixture.digest());
}

#[test]
fn package_file_count_and_size_are_bounded_before_payload_reads() {
    let oversized = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    rewrite_unsigned(oversized.root.path(), |manifest| {
        manifest.files[0].size = 16 * 1024 * 1024 + 1;
    });
    assert_eq!(
        load_error(oversized.root.path(), &local_context()),
        PackageError::Closure
    );

    let excessive_count = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    rewrite_unsigned(excessive_count.root.path(), |manifest| {
        let template = manifest.files[0].clone();
        while manifest.files.len() <= 1_024 {
            let mut entry = template.clone();
            entry.path = format!("source/padding/{:04}", manifest.files.len());
            manifest.files.push(entry);
        }
        manifest
            .files
            .sort_by(|left, right| left.path.cmp(&right.path));
    });
    assert_eq!(
        load_error(excessive_count.root.path(), &local_context()),
        PackageError::Integrity
    );
}

#[test]
fn package_apply_and_startup_errors_are_closed_and_value_free() {
    let rendered = format!(
        "{:?} {:?} {:?}",
        PackageError::Binding,
        MigrationError::ApplyFailed,
        StartupError::DatabaseUnready
    );
    for forbidden in [
        "source/modules/core",
        "CREATE TABLE",
        "signatureHex",
        "public-key-canary",
        "postgresql://",
        "registry_data",
    ] {
        assert!(!rendered.contains(forbidden));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_migration_role_is_refused_before_initial_control_plane_or_ddl() {
    let database = TestDatabase::create(1).await;
    let fixture = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let package = load_package(fixture.root.path(), &local_context())
        .expect("initial package verifies before role enforcement");
    let refused = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.runtime_config,
        &package,
        ActivationDeployment::new("local", INSTANCE, DATABASE),
        ApplyPrecondition::InitialActivation,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(1))
            .expect("test apply timeouts are bounded"),
        database.activation_audit(),
    ))
    .await;
    assert_eq!(refused.err(), Some(MigrationError::ApplyFailed));
    let state_table: Option<String> = database
        .admin
        .query_one(
            "SELECT to_regclass('registry_internal.registry_state')::text",
            &[],
        )
        .await
        .expect("the administrator can inspect control-plane absence")
        .get(0);
    assert_eq!(state_table, None);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_schema_fingerprint_mismatch_is_durably_failed_and_never_ready() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs prerequisite");
    let fixture = PackageFixture::build(None, fingerprint(7), PlanChoice::Schema);
    let initial_context = fixture.context();
    let package = load_package(fixture.root.path(), &initial_context)
        .expect("production-shaped package verifies before catalog apply");
    let refused = apply_package(
        &database,
        &package,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(refused.err(), Some(MigrationError::ApplyFailed));
    let state = registry_state_snapshot(&database.admin).await;
    assert_eq!(state.5, "failed");
    assert_eq!(state.6.as_deref(), Some(package.package_digest()));
    let ledger = migration_ledger_snapshot(&database.admin).await;
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].0, None);
    assert_eq!(ledger[0].1, package.package_digest());
    assert_eq!(ledger[0].4, "failed");
    // The state row of a failed initial activation names the target itself,
    // yet the durable state shows it failed, so the attempt's audit request
    // is answered failed rather than unfinished.
    let audited = database
        .activation_audit_entries()
        .into_iter()
        .filter(|entry| entry["schema"] == "breg-activation-audit/v1")
        .map(|entry| {
            (
                entry["phase"].as_str().unwrap_or_default().to_owned(),
                entry["record"]["outcome"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        audited,
        vec![
            ("request".to_owned(), "started".to_owned()),
            ("response".to_owned(), "failed".to_owned()),
        ]
    );

    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool.get_for_test().await.expect("runtime connects");
    let startup_context = fixture.context();
    let startup = prepare_startup(
        fixture.root.path(),
        &startup_context,
        DATABASE,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await;
    assert_eq!(startup.err(), Some(StartupError::DatabaseUnready));
    drop(runtime);
    database.cleanup().await;
}

/// A failed initial activation leaves a state row naming its own target,
/// yet the ledger records no applied activation, so the recorded state says
/// so and a plan of the same package reports the initial activation the
/// next apply resumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_initial_activation_is_recorded_unapplied_and_plans_as_its_resume() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs prerequisite");
    let fixture = PackageFixture::build(None, fingerprint(7), PlanChoice::Schema);
    let context = fixture.context();
    let package = load_package(fixture.root.path(), &context)
        .expect("production-shaped package verifies before catalog apply");
    let refused = apply_package(
        &database,
        &package,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(refused.err(), Some(MigrationError::ApplyFailed));
    let failed_activation: String = database
        .admin
        .query_one(
            "SELECT activation_id::text FROM registry_internal.registry_migrations",
            &[],
        )
        .await
        .expect("the one ledger entry reads")
        .get(0);

    let timeouts = ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(1))
        .expect("test timeouts are bounded");
    let recorded = read_recorded_registry_state(
        &database.migration_config,
        &package.manifest().package_id,
        &database.migration_role,
        timeouts,
    )
    .await
    .expect("the recorded state reads")
    .expect("the failed initial activation left a state row");
    assert!(!recorded.ready);
    assert!(
        !recorded.activation_applied,
        "the ledger records no applied activation"
    );

    let plan = plan_verified_package(ApplyVerifiedPackageRequest::plan(
        &database.migration_config,
        &package,
        ActivationDeployment::new("local", INSTANCE, DATABASE),
        ApplyPrecondition::InitialActivation,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        timeouts,
    ))
    .await
    .expect("the plan reports the interrupted initial activation");
    assert_eq!(plan.activation, PlannedActivation::Initial);
    assert_eq!(plan.resumes_activation_id, Some(failed_activation));
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_package_startup_apply_failure_and_old_process_are_closed() {
    let database = TestDatabase::create(1).await;
    let _unused_by_this_slice = &database.tls_runtime_config;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs prerequisite");
    let (mut migration, migration_task) = database.connect_migration().await;
    let first = PackageFixture::build(None, fingerprint(1), PlanChoice::Schema);
    let first_for_install = load_package(first.root.path(), &local_context())
        .expect("initial package verifies before database installation");
    let initial_fingerprint_transaction = migration
        .transaction()
        .await
        .expect("initial fingerprint rehearsal transaction starts");
    install_compiled_schema(
        &initial_fingerprint_transaction,
        first_for_install.registry(),
        &database.runtime_role,
    )
    .await
    .expect("initial fingerprint rehearsal installs the exact compiled Registry schema");
    let first_catalog = ExpectedManagedCatalog::compiled(first_for_install.registry());
    let schema = managed_schema_fingerprint(
        &initial_fingerprint_transaction,
        &database.runtime_role,
        &first_catalog,
    )
    .await
    .expect("initial compiled fingerprint computes");
    initial_fingerprint_transaction
        .rollback()
        .await
        .expect("initial fingerprint rehearsal leaves no target objects");
    rewrite_unsigned(first.root.path(), |manifest| {
        manifest.schema_fingerprint.clone_from(&schema);
    });
    let first_for_state = load_package(first.root.path(), &local_context())
        .expect("initial package reloads after finalized schema fingerprint");
    let first_digest = first_for_state.package_digest().to_owned();
    let wrong_migration_role = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.runtime_config,
        &first_for_state,
        ActivationDeployment::new("local", INSTANCE, DATABASE),
        ApplyPrecondition::InitialActivation,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(1))
            .expect("test apply timeouts are bounded"),
        database.activation_audit(),
    ))
    .await;
    assert_eq!(
        wrong_migration_role.err(),
        Some(MigrationError::ApplyFailed),
        "the exact configured migration role is verified before control-plane DDL"
    );
    let state_table: Option<String> = database
        .admin
        .query_one(
            "SELECT to_regclass('registry_internal.registry_state')::text",
            &[],
        )
        .await
        .expect("control-plane absence can be inspected after refused intent")
        .get(0);
    assert_eq!(state_table, None);
    let initial = apply_package(
        &database,
        &first_for_state,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .expect("one coordinator durably applies and activates the initial verified package");
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool.get_for_test().await.expect("runtime connects");
    let first_startup = local_context();
    prepare_startup(
        first.root.path(),
        &first_startup,
        DATABASE,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("matching package produces the listener gate");
    drop(runtime);
    // The recorded instance and environment are the database's own, so only
    // the registry and the database id bind a startup to this database.
    for (column, original, expected) in [
        (
            "package_id",
            initial.package_id.as_str(),
            StartupError::DatabaseUnready,
        ),
        (
            "database_id",
            initial.database_id.as_str(),
            StartupError::DatabaseIdentityMismatch,
        ),
    ] {
        database
            .admin
            .execute(
                &format!(
                    "UPDATE registry_internal.registry_state SET {column} = $1 WHERE singleton"
                ),
                &[&format!("wrong-{column}")],
            )
            .await
            .expect("test can seed durable identity drift");
        let mut runtime = pool
            .get_for_test()
            .await
            .expect("runtime reconnects for durable identity drift proof");
        let refused = prepare_startup(
            first.root.path(),
            &first_startup,
            DATABASE,
            &mut runtime,
            &database.migration_role,
            &database.runtime_role,
        )
        .await;
        assert_eq!(
            refused.err(),
            Some(expected),
            "startup refuses durable {column} drift"
        );
        drop(runtime);
        database
            .admin
            .execute(
                &format!(
                    "UPDATE registry_internal.registry_state SET {column} = $1 WHERE singleton"
                ),
                &[&original],
            )
            .await
            .expect("test restores durable identity");
    }

    let tampered_startup = PackageFixture::build(None, schema.clone(), PlanChoice::Schema);
    let tampered_artifact = first_generated_path(tampered_startup.root.path());
    fs::write(tampered_artifact, b"pre-listener tamper").expect("startup artifact tamper writes");
    let mut runtime = pool.get_for_test().await.expect("runtime reconnects");
    let no_listener_gate = prepare_startup(
        tampered_startup.root.path(),
        &first_startup,
        DATABASE,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await;
    assert!(matches!(
        no_listener_gate.err(),
        Some(StartupError::PackageEnvelopeRefused(_))
    ));
    drop(runtime);

    let second =
        PackageFixture::build(Some(&first_digest), schema.clone(), PlanChoice::SecondTable);
    let activation_context = local_context();
    let provisional_second = load_package(second.root.path(), &activation_context)
        .expect("successor package verifies before apply");
    let transaction = migration
        .transaction()
        .await
        .expect("target fingerprint transaction starts");
    for statement in &provisional_second.manifest().migration_plan.statements {
        transaction
            .batch_execute(&statement.sql)
            .await
            .expect("exact additive target plan applies in fingerprint transaction");
    }
    let provisional_second_table =
        &provisional_second.registry().entities()["second-record"].physical_table;
    transaction
        .batch_execute(&format!(
            "REVOKE ALL ON TABLE registry_data.{} FROM PUBLIC, \"{}\";
             GRANT SELECT, INSERT ON TABLE registry_data.{} TO \"{}\";",
            quote_identifier(provisional_second_table),
            database.runtime_role.as_str(),
            quote_identifier(provisional_second_table),
            database.runtime_role.as_str(),
        ))
        .await
        .expect("target fingerprint transaction installs the exact compiled runtime ACL");
    reconcile_view_acl_for_fingerprint(
        &transaction,
        provisional_second.registry(),
        database.runtime_role.as_str(),
    )
    .await;
    let second_catalog = ExpectedManagedCatalog::compiled(provisional_second.registry());
    let target_schema =
        managed_schema_fingerprint(&transaction, &database.runtime_role, &second_catalog)
            .await
            .expect("target compiled fingerprint computes from the exact plan");
    transaction
        .rollback()
        .await
        .expect("fingerprint transaction rolls back");
    rewrite_unsigned(second.root.path(), |manifest| {
        manifest.schema_fingerprint.clone_from(&target_schema);
    });
    let verified_second = load_package(second.root.path(), &activation_context)
        .expect("successor package verifies with its target fingerprint");
    migration_task.abort();

    let claims = ClaimContext::for_compiled(
        first_for_install.registry(),
        "neutral-record",
        Some("record-reader".to_owned()),
        "reader",
        None,
        Vec::new(),
    )
    .expect("compiled claims are accepted");
    let package_lock = RegistryLockKey::derive(&verified_second.manifest().package_id)
        .expect("verified package lock key derives");
    let mut wrong_record_client = pool
        .get_for_test()
        .await
        .expect("record client connects for durable identity refusal");
    let mut wrong_expected = initial.clone();
    wrong_expected.database_id = "wrong-database".to_owned();
    match begin_record_transaction(
        &mut wrong_record_client,
        package_lock,
        Duration::from_secs(1),
        &wrong_expected,
        &claims,
    )
    .await
    {
        Err(registry_breg::postgres::PostgresKernelError::RegistryUnavailable) => {}
        Err(_) => panic!("record transaction returned the wrong value-free error"),
        Ok(transaction) => {
            transaction
                .rollback()
                .await
                .expect("unexpected transaction rolls back");
            panic!("record transaction accepted a wrong durable binding");
        }
    }
    drop(wrong_record_client);
    let drift_before_apply = registry_state_snapshot(&database.admin).await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state SET package_id = $1 WHERE singleton",
            &[&"wrong-package"],
        )
        .await
        .expect("test can seed durable package_id drift");
    let drifted_state = registry_state_snapshot(&database.admin).await;
    let refused_apply = apply_package(
        &database,
        &verified_second,
        ApplyPrecondition::Successor { current: &initial },
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(refused_apply.err(), Some(MigrationError::ApplyFailed));
    assert_eq!(
        registry_state_snapshot(&database.admin).await,
        drifted_state,
        "apply refusal must not mutate a wrong durable binding"
    );
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state SET package_id = $1 WHERE singleton",
            &[&initial.package_id],
        )
        .await
        .expect("test restores durable package_id");
    assert_eq!(
        registry_state_snapshot(&database.admin).await,
        drift_before_apply
    );
    let mut record_client = pool.get_for_test().await.expect("record client connects");
    let held_record = begin_record_transaction(
        &mut record_client,
        package_lock,
        Duration::from_secs(1),
        &initial,
        &claims,
    )
    .await
    .expect("record transaction holds the package shared lock");
    let blocked = apply_package(
        &database,
        &verified_second,
        ApplyPrecondition::Successor { current: &initial },
        Duration::from_millis(50),
        Duration::from_secs(1),
    )
    .await;
    assert!(
        blocked.is_err(),
        "package apply cannot pass a concurrent record transaction"
    );
    let blocked_state = database
        .admin
        .query_one(
            "SELECT maintenance_status, active_package_digest
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await
        .expect("blocked apply leaves state readable");
    assert_eq!(blocked_state.get::<_, String>(0), "ready");
    assert_eq!(blocked_state.get::<_, String>(1), initial.package_digest);
    held_record
        .rollback()
        .await
        .expect("record transaction releases the shared lock");
    drop(record_client);

    let (mut ddl_blocker, ddl_blocker_task) = database.connect_migration().await;
    let ddl_blocker_pid: i32 = ddl_blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("DDL blocker backend identity reads")
        .get(0);
    let blocked_ddl = ddl_blocker
        .transaction()
        .await
        .expect("DDL cancellation blocker transaction starts");
    blocked_ddl
        .batch_execute(&verified_second.manifest().migration_plan.statements[0].sql)
        .await
        .expect("uncommitted target object deterministically blocks package DDL");
    let interrupted = {
        let interrupted_apply = apply_package(
            &database,
            &verified_second,
            ApplyPrecondition::Successor { current: &initial },
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        tokio::pin!(interrupted_apply);
        tokio::select! {
            result = &mut interrupted_apply => {
                panic!("blocked apply completed before deterministic connection interruption: {result:?}")
            }
            () = wait_for_maintenance_status(&database.admin, "applying") => {}
        }
        let apply_pid = tokio::select! {
            result = &mut interrupted_apply => {
                panic!("apply completed before its dedicated connection could be interrupted: {result:?}")
            }
            pid = wait_for_blocked_apply_backend(
                &database.admin,
                database.migration_role.as_str(),
                ddl_blocker_pid,
            ) => pid,
        };
        let terminated: bool = database
            .admin
            .query_one("SELECT pg_terminate_backend($1)", &[&apply_pid])
            .await
            .expect("administrator interrupts the exact dedicated apply connection")
            .get(0);
        assert!(terminated);
        interrupted_apply.await
    };
    let interrupted_error = interrupted.expect_err("terminated apply connection fails closed");
    assert_eq!(interrupted_error, MigrationError::ApplyFailed);
    let diagnostic = format!("{interrupted_error:?} {interrupted_error}");
    for forbidden in [
        verified_second.package_digest(),
        provisional_second_table.as_str(),
        "registry_data",
        "pg_terminate_backend",
    ] {
        assert!(!diagnostic.contains(forbidden));
    }
    blocked_ddl
        .rollback()
        .await
        .expect("DDL blocker rolls back after apply connection interruption");
    ddl_blocker_task.abort();
    let interrupted_state = registry_state_snapshot(&database.admin).await;
    assert_eq!(interrupted_state.2, initial.package_digest);
    assert_eq!(interrupted_state.5, "applying");
    assert_eq!(
        interrupted_state.6.as_deref(),
        Some(verified_second.package_digest())
    );
    assert_eq!(
        migration_ledger_snapshot(&database.admin)
            .await
            .last()
            .map(|entry| entry.4.as_str()),
        Some("applying"),
        "connection loss leaves a durable non-ready target without unsafe activation"
    );
    {
        let mut interrupted_record_client = pool
            .get_for_test()
            .await
            .expect("runtime reconnects after apply connection loss");
        match begin_record_transaction(
            &mut interrupted_record_client,
            package_lock,
            Duration::from_secs(1),
            &initial,
            &claims,
        )
        .await
        {
            Err(registry_breg::postgres::PostgresKernelError::RegistryUnavailable) => {}
            Err(_) => panic!("interrupted maintenance returned the wrong value-free refusal"),
            Ok(transaction) => {
                transaction
                    .rollback()
                    .await
                    .expect("unexpected interrupted record transaction rolls back");
                panic!("record work entered while interrupted maintenance was unavailable");
            }
        };
    }

    let active = apply_package(
        &database,
        &verified_second,
        ApplyPrecondition::Successor { current: &initial },
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .expect("exact rederived schema statement and activation succeed");
    assert_eq!(active.package_digest, verified_second.package_digest());
    let activated_state = registry_state_snapshot(&database.admin).await;
    assert_eq!(activated_state.0, active.package_id);
    assert_eq!(activated_state.1, active.database_id);
    assert_eq!(activated_state.3, active.activation_id);
    let applied_ledger = migration_ledger_snapshot(&database.admin).await;
    assert_eq!(applied_ledger.len(), 2);
    assert_eq!(applied_ledger[0].0, None);
    assert_eq!(applied_ledger[0].1, first_digest);
    assert_eq!(applied_ledger[0].2, 1);
    assert_eq!(applied_ledger[0].4, "applied");
    assert_eq!(
        applied_ledger[1].0.as_deref(),
        Some(initial.package_digest.as_str())
    );
    assert_eq!(applied_ledger[1].1, active.package_digest);
    assert_eq!(applied_ledger[1].2, 2);
    assert_eq!(applied_ledger[1].4, "applied");
    assert_eq!(
        applied_ledger[1].3,
        verified_second
            .manifest()
            .migration_plan
            .statements
            .iter()
            .map(|statement| format!("sha256:{}", hex(&Sha256::digest(statement.sql.as_bytes()))))
            .collect::<Vec<_>>()
    );
    let immutable_replay = apply_package(
        &database,
        &verified_second,
        ApplyPrecondition::Successor { current: &initial },
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(immutable_replay.err(), Some(MigrationError::ApplyFailed));
    assert_eq!(
        migration_ledger_snapshot(&database.admin).await,
        applied_ledger,
        "an applied migration row is never rewritten"
    );

    let mut runtime = pool.get_for_test().await.expect("runtime reconnects");
    let second_startup = local_context();
    prepare_startup(
        second.root.path(),
        &second_startup,
        DATABASE,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("activated package is listener-ready");
    let second_table = format!(
        "registry_data.{}",
        verified_second.registry().entities()["second-record"].physical_table
    );
    let runtime_privileges = runtime
        .query_one(
            "SELECT has_table_privilege(current_user, $1, 'SELECT'),
                    has_table_privilege(current_user, $1, 'INSERT'),
                    has_table_privilege(current_user, $1, 'UPDATE')",
            &[&second_table],
        )
        .await
        .expect("successor runtime privilege probe succeeds");
    assert!(runtime_privileges.get::<_, bool>(0));
    assert!(runtime_privileges.get::<_, bool>(1));
    assert!(!runtime_privileges.get::<_, bool>(2));
    let old_process = prepare_startup(
        first.root.path(),
        &first_startup,
        DATABASE,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await;
    assert_eq!(old_process.err(), Some(StartupError::ActivePackageMismatch));
    drop(runtime);

    let wrong_schema =
        PackageFixture::build(Some(&first_digest), fingerprint(7), PlanChoice::SecondTable);
    let wrong_digest = wrong_schema.digest();
    let wrong_startup = local_context();
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
             SET active_package_digest = $1
             WHERE singleton",
            &[&wrong_digest],
        )
        .await
        .expect("test binds the active revision while leaving the real schema fingerprint intact");
    let mut runtime = pool.get_for_test().await.expect("runtime reconnects");
    let refused = prepare_startup(
        wrong_schema.root.path(),
        &wrong_startup,
        DATABASE,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await;
    assert_eq!(refused.err(), Some(StartupError::DatabaseUnready));
    drop(runtime);
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
             SET active_package_digest = $1
             WHERE singleton",
            &[&active.package_digest],
        )
        .await
        .expect("test restores the active revision after schema mismatch proof");

    let third = PackageFixture::build(
        Some(&active.package_digest),
        target_schema.clone(),
        PlanChoice::ThirdTable,
    );
    let third_context = local_context();
    let provisional_third =
        load_package(third.root.path(), &third_context).expect("third package verifies");
    let (mut fingerprint_connection, fingerprint_task) = database.connect_migration().await;
    let transaction = fingerprint_connection
        .transaction()
        .await
        .map_err(|_| ())
        .expect("third target fingerprint transaction starts");
    for statement in &provisional_third.manifest().migration_plan.statements {
        transaction
            .batch_execute(&statement.sql)
            .await
            .map_err(|_| ())
            .expect("third exact additive plan applies in fingerprint transaction");
    }
    reconcile_view_acl_for_fingerprint(
        &transaction,
        provisional_third.registry(),
        database.runtime_role.as_str(),
    )
    .await;
    let third_catalog = ExpectedManagedCatalog::compiled(provisional_third.registry());
    let third_schema =
        managed_schema_fingerprint(&transaction, &database.runtime_role, &third_catalog)
            .await
            .map_err(|_| ())
            .expect("third target fingerprint computes");
    transaction
        .rollback()
        .await
        .map_err(|_| ())
        .expect("third target fingerprint transaction rolls back");
    fingerprint_task.abort();
    rewrite_unsigned(third.root.path(), |manifest| {
        manifest.schema_fingerprint.clone_from(&third_schema);
    });
    let verified_third = load_package(third.root.path(), &third_context)
        .expect("third package verifies with its target fingerprint");
    let table_sql = &verified_third.manifest().migration_plan.statements[0].sql;
    database
        .admin
        .batch_execute(table_sql)
        .await
        .map_err(|_| ())
        .expect("administrator injects an existing target table");
    let failed = apply_package(
        &database,
        &verified_third,
        ApplyPrecondition::Successor { current: &active },
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await;
    assert!(
        failed.is_err(),
        "injected exact DDL failure refuses activation"
    );
    let status: String = database
        .admin
        .query_one(
            "SELECT maintenance_status FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("maintenance state reads")
        .get(0);
    assert_eq!(status, "failed");
    let failed_ledger = migration_ledger_snapshot(&database.admin).await;
    let active_startup_package = load_package(second.root.path(), &second_startup)
        .expect("the active package still verifies only for startup intent");
    let refused_noop_clear = apply_package(
        &database,
        &active_startup_package,
        ApplyPrecondition::Successor { current: &active },
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(
        refused_noop_clear.err(),
        Some(MigrationError::AlreadyActive),
        "a no-op startup package cannot clear failed maintenance"
    );
    assert_eq!(
        migration_ledger_snapshot(&database.admin).await,
        failed_ledger
    );

    let wrong_recovery = PackageFixture::build(
        Some(&active.package_digest),
        third_schema.clone(),
        PlanChoice::ThirdTable,
    );
    let verified_wrong_recovery = load_package(wrong_recovery.root.path(), &third_context)
        .expect("different recovery target verifies as a package");
    let refused_recovery = apply_package(
        &database,
        &verified_wrong_recovery,
        ApplyPrecondition::Successor { current: &active },
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await;
    assert!(
        refused_recovery.is_err(),
        "failed maintenance refuses a different package target"
    );
    let failed_target = database
        .admin
        .query_one(
            "SELECT maintenance_status, maintenance_target_package_digest
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await
        .expect("failed target remains readable");
    assert_eq!(failed_target.get::<_, String>(0), "failed");
    assert_eq!(
        failed_target.get::<_, String>(1),
        verified_third.package_digest()
    );

    let third_table = &verified_third.registry().entities()["third-record"].physical_table;
    database
        .admin
        .batch_execute(&format!(
            "DROP TABLE registry_data.{}",
            quote_identifier(third_table)
        ))
        .await
        .map_err(|_| ())
        .expect("operator removes the conflicting object");
    let recovered = apply_package(
        &database,
        &verified_third,
        ApplyPrecondition::Successor { current: &active },
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .expect("the exact failed package resumes after operator repair");
    assert_eq!(recovered.package_digest, verified_third.package_digest());
    let recovered_status: String = database
        .admin
        .query_one(
            "SELECT maintenance_status FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("recovered maintenance state reads")
        .get(0);
    assert_eq!(recovered_status, "ready");

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successor_apply_refuses_to_strand_retained_webhook_work() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs prerequisite");
    let (mut migration, migration_task) = database.connect_migration().await;
    let destination_fixture = EventDestinationCompatibilityFixture::create();

    let first = PackageFixture::build(None, fingerprint(1), PlanChoice::WebhookSchema);
    let provisional_first = load_package(first.root.path(), &local_context())
        .expect("initial webhook package verifies before fingerprinting");
    let transaction = migration
        .transaction()
        .await
        .expect("initial webhook fingerprint transaction starts");
    install_compiled_schema(
        &transaction,
        provisional_first.registry(),
        &database.runtime_role,
    )
    .await
    .expect("initial webhook schema installs for fingerprinting");
    let first_catalog = ExpectedManagedCatalog::compiled(provisional_first.registry());
    let first_fingerprint =
        managed_schema_fingerprint(&transaction, &database.runtime_role, &first_catalog)
            .await
            .expect("initial webhook fingerprint derives");
    transaction
        .rollback()
        .await
        .expect("initial webhook fingerprint transaction rolls back");
    rewrite_unsigned(first.root.path(), |manifest| {
        manifest.schema_fingerprint.clone_from(&first_fingerprint);
    });
    let verified_first = load_package(first.root.path(), &local_context())
        .expect("initial webhook package reloads with exact fingerprint");
    let active = apply_package(
        &database,
        &verified_first,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .expect("initial webhook package activates");

    let exact_inventory = destination_fixture.inventory(verified_first.registry(), "/events/v1");
    let exact_digest = exact_inventory
        .binding_digest("neutral-events")
        .expect("compiled logical destination has an activated digest")
        .to_owned();
    let data_schema = verified_first.registry().event_deliveries().deliveries[0]
        .data_schema
        .as_str();
    let pending_event = Uuid::new_v4();
    insert_upgrade_webhook_delivery(
        &database,
        &active,
        pending_event,
        "neutral-events",
        &exact_digest,
        data_schema,
        UpgradeDeliveryState::Pending,
    )
    .await;
    insert_upgrade_webhook_delivery(
        &database,
        &active,
        Uuid::new_v4(),
        "removed-delivered-destination",
        &fingerprint(31),
        data_schema,
        UpgradeDeliveryState::Delivered,
    )
    .await;
    let erased_pending_event = Uuid::new_v4();
    insert_upgrade_webhook_delivery(
        &database,
        &active,
        erased_pending_event,
        "removed-erased-pending-destination",
        &fingerprint(34),
        data_schema,
        UpgradeDeliveryState::Pending,
    )
    .await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_outbox
             SET payload = NULL
             WHERE event_id = $1",
            &[&erased_pending_event],
        )
        .await
        .expect("upgrade test erases one pending payload before retention cleanup");
    let expired_pending_event = Uuid::new_v4();
    insert_upgrade_webhook_delivery(
        &database,
        &active,
        expired_pending_event,
        "removed-expired-pending-destination",
        &fingerprint(35),
        data_schema,
        UpgradeDeliveryState::Pending,
    )
    .await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_outbox
             SET payload_expires_at = transaction_timestamp() - interval '1 second'
             WHERE event_id = $1",
            &[&expired_pending_event],
        )
        .await
        .expect("upgrade test expires one pending payload before retention cleanup");
    let replayable_dead_letter_event = Uuid::new_v4();
    insert_upgrade_webhook_delivery(
        &database,
        &active,
        replayable_dead_letter_event,
        "removed-dead-letter-destination",
        &fingerprint(32),
        data_schema,
        UpgradeDeliveryState::DeadLettered,
    )
    .await;
    insert_upgrade_webhook_delivery(
        &database,
        &active,
        Uuid::new_v4(),
        "removed-expired-destination",
        &fingerprint(33),
        data_schema,
        UpgradeDeliveryState::Expired,
    )
    .await;

    let second = PackageFixture::build(
        Some(&active.package_digest),
        first_fingerprint,
        PlanChoice::WebhookSecondTable,
    );
    let activation_context = local_context();
    let provisional_second = load_package(second.root.path(), &activation_context)
        .expect("unrelated additive webhook successor verifies before fingerprinting");
    let transaction = migration
        .transaction()
        .await
        .expect("successor webhook fingerprint transaction starts");
    for statement in &provisional_second.manifest().migration_plan.statements {
        transaction
            .batch_execute(&statement.sql)
            .await
            .expect("successor additive DDL applies for fingerprinting");
    }
    let second_table = &provisional_second.registry().entities()["second-record"].physical_table;
    transaction
        .batch_execute(&format!(
            "REVOKE ALL ON TABLE registry_data.{} FROM PUBLIC, \"{}\";
             GRANT SELECT, INSERT ON TABLE registry_data.{} TO \"{}\";",
            quote_identifier(second_table),
            database.runtime_role.as_str(),
            quote_identifier(second_table),
            database.runtime_role.as_str(),
        ))
        .await
        .expect("successor fingerprint transaction installs target runtime ACL");
    reconcile_view_acl_for_fingerprint(
        &transaction,
        provisional_second.registry(),
        database.runtime_role.as_str(),
    )
    .await;
    let second_catalog = ExpectedManagedCatalog::compiled(provisional_second.registry());
    let second_fingerprint =
        managed_schema_fingerprint(&transaction, &database.runtime_role, &second_catalog)
            .await
            .expect("successor webhook fingerprint derives");
    transaction
        .rollback()
        .await
        .expect("successor webhook fingerprint transaction rolls back");
    rewrite_unsigned(second.root.path(), |manifest| {
        manifest.schema_fingerprint.clone_from(&second_fingerprint);
    });
    let verified_second = load_package(second.root.path(), &activation_context)
        .expect("successor webhook package reloads with exact fingerprint");
    migration_task.abort();

    let before_refusals = registry_state_snapshot(&database.admin).await;
    let changed_inventory =
        destination_fixture.inventory(verified_second.registry(), "/events/changed");
    let removed_inventory = EventDestinationCompatibilityInventory::default();
    let changed_refused = apply_package_with_event_destination_compatibility(
        &database,
        &verified_second,
        ApplyPrecondition::Successor { current: &active },
        &changed_inventory,
    )
    .await;
    assert_eq!(changed_refused.err(), Some(MigrationError::ApplyFailed));
    assert_eq!(
        registry_state_snapshot(&database.admin).await,
        before_refusals,
        "a changed pending binding is refused before maintenance state changes"
    );

    let lease_token = Uuid::new_v4();
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_delivery_state
             SET state = 'leased', attempt = 1, next_attempt_at = NULL,
                 attempt_started_at = transaction_timestamp(),
                 lease_expires_at = transaction_timestamp() + interval '1 hour',
                 lease_token = $2, updated_at = transaction_timestamp()
             WHERE event_id = $1",
            &[&pending_event, &lease_token],
        )
        .await
        .expect("upgrade test simulates retained leased work");
    let removed_refused = apply_package_with_event_destination_compatibility(
        &database,
        &verified_second,
        ApplyPrecondition::Successor { current: &active },
        &removed_inventory,
    )
    .await;
    assert_eq!(removed_refused.err(), Some(MigrationError::ApplyFailed));
    assert_eq!(
        registry_state_snapshot(&database.admin).await,
        before_refusals,
        "a removed leased binding is refused before maintenance state changes"
    );
    let retained_lease: String = database
        .admin
        .query_one(
            "SELECT state FROM registry_internal.registry_webhook_delivery_state
             WHERE event_id = $1",
            &[&pending_event],
        )
        .await
        .expect("leased state remains after refused activation")
        .get(0);
    assert_eq!(retained_lease, "leased");
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_delivery_state
             SET state = 'pending', attempt = 0,
                 next_attempt_at = transaction_timestamp(), attempt_started_at = NULL,
                 lease_expires_at = NULL, lease_token = NULL,
                 updated_at = transaction_timestamp()
             WHERE event_id = $1 AND state = 'leased' AND lease_token = $2",
            &[&pending_event, &lease_token],
        )
        .await
        .expect("upgrade test restores pending old delivery for worker proof");

    let target_inventory = destination_fixture.inventory(verified_second.registry(), "/events/v1");
    assert_eq!(
        target_inventory.binding_digest("neutral-events"),
        Some(exact_digest.as_str())
    );
    let replayable_dead_letter_refused = apply_package_with_event_destination_compatibility(
        &database,
        &verified_second,
        ApplyPrecondition::Successor { current: &active },
        &target_inventory,
    )
    .await;
    assert_eq!(
        replayable_dead_letter_refused.err(),
        Some(MigrationError::ApplyFailed)
    );
    assert_eq!(
        registry_state_snapshot(&database.admin).await,
        before_refusals,
        "an incompatible retained replayable dead letter is refused before maintenance state changes"
    );
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_webhook_deliveries
             SET operator_replay = false
             WHERE event_id = $1",
            &[&replayable_dead_letter_event],
        )
        .await
        .expect("upgrade test disables replay for one retained dead letter");
    let upgraded = apply_package_with_event_destination_compatibility(
        &database,
        &verified_second,
        ApplyPrecondition::Successor { current: &active },
        &target_inventory,
    )
    .await
    .expect("an unrelated additive successor with the exact binding activates");
    assert_eq!(
        ledger_apply_order(&database, &upgraded.activation_id).await,
        2
    );
    let after_upgrade = registry_state_snapshot(&database.admin).await;
    assert_eq!(after_upgrade.3, upgraded.activation_id);
    assert_eq!(after_upgrade.5, "ready");

    let retained = database
        .admin
        .query_one(
            "SELECT delivery.package_revision, delivery.logical_destination_id,
                    delivery.destination_binding_digest, state.state
             FROM registry_internal.registry_webhook_deliveries AS delivery
             JOIN registry_internal.registry_webhook_delivery_state AS state
               ON state.event_id = delivery.event_id
              AND state.compiled_delivery_id = delivery.compiled_delivery_id
             WHERE delivery.event_id = $1",
            &[&pending_event],
        )
        .await
        .expect("retained pre-upgrade delivery remains queryable");
    assert_eq!(retained.get::<_, String>(0), active.activation_id);
    assert_eq!(retained.get::<_, String>(1), "neutral-events");
    assert_eq!(retained.get::<_, String>(2), exact_digest);
    assert_eq!(retained.get::<_, String>(3), "pending");
    let ignored_event_ids = vec![erased_pending_event, expired_pending_event];
    let ignored_pending: Vec<(String, bool, bool)> = database
        .admin
        .query(
            "SELECT state.state, outbox.payload IS NULL,
                    outbox.payload_expires_at <= transaction_timestamp()
             FROM registry_internal.registry_webhook_delivery_state AS state
             JOIN registry_internal.registry_outbox AS outbox
               ON outbox.event_id = state.event_id
             WHERE state.event_id = ANY($1::uuid[])
             ORDER BY state.event_id",
            &[&ignored_event_ids],
        )
        .await
        .expect("ignored pending retention states remain inspectable")
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    assert_eq!(ignored_pending.len(), 2);
    assert!(ignored_pending
        .iter()
        .all(|(state, payload_erased, payload_expired)| {
            state == "pending" && (*payload_erased || *payload_expired)
        }));

    database.cleanup().await;
}

async fn reconcile_view_acl_for_fingerprint(
    client: &impl GenericClient,
    registry: &registry_breg::CompiledRegistry,
    runtime_role: &str,
) {
    for view in &registry.ddl().views {
        let schema = quote_identifier(&view.schema);
        let name = quote_identifier(&view.name);
        client
            .batch_execute(&format!(
                "REVOKE ALL ON TABLE {schema}.{name} FROM PUBLIC, \"{runtime_role}\";"
            ))
            .await
            .expect("fingerprint transaction reconciles compiled view revocations");
        if !view.runtime_privileges.is_empty() {
            let privileges = view
                .runtime_privileges
                .iter()
                .map(|privilege| privilege.as_sql())
                .collect::<Vec<_>>()
                .join(", ");
            client
                .batch_execute(&format!(
                    "GRANT {privileges} ON TABLE {schema}.{name} TO \"{runtime_role}\";"
                ))
                .await
                .expect("fingerprint transaction reconciles compiled view grants");
        }
    }
}

#[derive(Clone, Copy)]
enum PlanChoice {
    Schema,
    SecondTable,
    ThirdTable,
    WebhookSchema,
    WebhookSecondTable,
    TemporalSchema,
}

fn predecessor_plan_choice(plan: PlanChoice) -> PlanChoice {
    match plan {
        PlanChoice::Schema | PlanChoice::SecondTable => PlanChoice::Schema,
        PlanChoice::ThirdTable => PlanChoice::SecondTable,
        PlanChoice::WebhookSchema => PlanChoice::WebhookSchema,
        PlanChoice::WebhookSecondTable => PlanChoice::WebhookSchema,
        PlanChoice::TemporalSchema => PlanChoice::TemporalSchema,
    }
}

fn compile_fixture_registry(plan: PlanChoice) -> registry_breg::CompiledRegistry {
    let module_bytes = module_bytes(plan);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let project_bytes = project_bytes(&module_digest(&module));
    let project = parse_project_yaml(&project_bytes).expect("fixture project parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("fixture project compiles in production")
}

struct PackageFixture {
    root: TempRoot,
}

impl PackageFixture {
    fn build(prior_revision: Option<&str>, schema_fingerprint: String, plan: PlanChoice) -> Self {
        let root = TempRoot::create();
        let module_bytes = module_bytes(plan);
        let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
        let project_bytes = project_bytes(&module_digest(&module));
        let migration_plan = if prior_revision.is_none() {
            PackageMigrationPlanInput::InitialCompiledDdl
        } else {
            let prior_registry = compile_fixture_registry(predecessor_plan_choice(plan));
            PackageMigrationPlanInput::Successor {
                prior_registry: Box::new(prior_registry),
            }
        };
        let prepared = prepare_package(build_request(BuildRequestParts {
            prior_revision,
            schema_fingerprint,
            project_bytes,
            module_bytes,
            migration_plan,
        }))
        .expect("fixture package prepares");
        prepared
            .publish_to_directory(root.path())
            .expect("fixture package publishes");
        Self { root }
    }

    fn context(&self) -> PackageLoadContext<'static> {
        PackageLoadContext {
            database_initialization_environment: "production",
        }
    }

    fn digest(&self) -> String {
        package_digest_of(self.root.path())
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn create() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock follows epoch")
            .as_nanos();
        let parent = std::env::temp_dir()
            .canonicalize()
            .expect("temporary parent canonicalizes");
        let ordinal = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            "breg-package-{}-{nanos}-{ordinal}",
            std::process::id(),
        ));
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        if self
            .0
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("breg-package-"))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn project_bytes(module_digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}}},"publicService":{{"id":"neutral-registry-service","title":"Neutral Registry Catalog"}},"datasets":[{{"id":"neutral-registry","title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"neutral-registry-data-service","title":"Neutral Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["neutral-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    )
    .into_bytes()
}

fn project_bytes_without_manifest(module_digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"sourceRevision":"{SOURCE_REVISION}"}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    )
    .into_bytes()
}

fn project_bytes_with_source_revision(module_digest: &str, source_revision: &str) -> Vec<u8> {
    String::from_utf8(project_bytes(module_digest))
        .expect("fixture project is UTF-8")
        .replace(SOURCE_REVISION, source_revision)
        .into_bytes()
}

#[cfg(feature = "tooling")]
fn metadata_only_review_source(
    changes: &[registry_breg::package::CompiledRegistryChange],
    prior_revision: &str,
    prior_schema_fingerprint: &str,
    final_schema_fingerprint: &str,
) -> ReviewedMigrationSource {
    let mut covers = changes
        .iter()
        .filter(|change| change.class != CompiledRegistryChangeClass::CompatibleAdditive)
        .map(ReviewedChangeCover::from)
        .collect::<Vec<_>>();
    covers.sort();
    assert!(!covers.is_empty());
    let base = "modules/core/migrations/metadata-access";
    let descriptor = ReviewedMigrationDescriptor {
        id: "metadata-access".to_owned(),
        change_class: CompiledRegistryChangeClass::AccessOrDisclosureChange,
        covers,
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        history: None,
        lock_timeout_ms: 1000,
        statement_timeout_ms: 5000,
        steps: Vec::new(),
        pre_assertions: Vec::new(),
        post_assertions: Vec::new(),
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
    };
    let descriptor_bytes =
        canonicalize_json(&serde_json::to_value(descriptor).expect("descriptor serializes"))
            .expect("descriptor canonicalizes");
    let receipt = MigrationRehearsalReceipt {
        prior_package_digest: prior_revision.to_owned(),
        prior_schema_fingerprint: prior_schema_fingerprint.to_owned(),
        plan_sha256: format!("sha256:{}", hex(&Sha256::digest(&descriptor_bytes))),
        sql_sha256: Vec::new(),
        assertion_sha256: Vec::new(),
        fixture_inventory: Vec::new(),
        postgres_major: 16,
        row_assertions: Vec::new(),
        final_schema_fingerprint: final_schema_fingerprint.to_owned(),
    };
    ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: format!("{base}/descriptor.json"),
            bytes: descriptor_bytes,
        },
        files: vec![ReviewedMigrationFile {
            path: format!("{base}/rehearsal.json"),
            bytes: canonicalize_json(&serde_json::to_value(receipt).expect("receipt serializes"))
                .expect("receipt canonicalizes"),
        }],
    }
}

fn temporal_policy_module_bytes(snapshot: bool) -> Vec<u8> {
    temporal_policy_module_bytes_with(snapshot, "", "")
}

fn temporal_policy_module_bytes_with(
    snapshot: bool,
    extra_membership_fields: &str,
    reader_profile_extra: &str,
) -> Vec<u8> {
    let operations = if snapshot {
        r#""get","list","snapshot""#
    } else {
        r#""get","list""#
    };
    format!(
        r#"{{"id":"core","version":"1","entities":[{{"id":"neutral-record","primaryDataset":"neutral-registry","route":"neutral-records","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":8,"classification":"internal"}}],"accessProfiles":[{{"requiredScopes":"unrestricted","rowBoundaries":"unrestricted", "id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"]}}]}},{{"id":"membership","primaryDataset":"neutral-registry","route":"memberships","mutationMode":"mutable","fields":[{{"id":"person","type":"string","maxLength":32,"required":true,"classification":"internal"}},{{"id":"valid-from","type":"date","required":true,"classification":"internal"}},{{"id":"valid-to","type":"date","classification":"internal"}}{extra_membership_fields}],"temporal":{{"startField":"valid-from","endField":"valid-to"}},"constraints":[{{"id":"membership-window","kind":"temporal-non-overlap","scopeFields":["person"],"startField":"valid-from","endField":"valid-to"}}],"accessProfiles":[{{"requiredScopes":"unrestricted","rowBoundaries":"unrestricted", "id":"reader","principalClaim":"principal","operations":[{operations}],"readableFields":["person","valid-from","valid-to"],"filterableFields":["person","valid-from"]{reader_profile_extra}}}]}}]}}"#
    )
    .into_bytes()
}

fn publish_temporal_policy_package(
    prior_revision: Option<&str>,
    schema_fingerprint: String,
    module_bytes: Vec<u8>,
    migration_plan: PackageMigrationPlanInput,
) -> TempRoot {
    let root = TempRoot::create();
    let module = parse_module_yaml(&module_bytes).expect("temporal policy module parses");
    let prepared = prepare_package(build_request(BuildRequestParts {
        prior_revision,
        schema_fingerprint,
        project_bytes: project_bytes(&module_digest(&module)),
        module_bytes,
        migration_plan,
    }))
    .expect("temporal policy package prepares");
    prepared
        .publish_to_directory(root.path())
        .expect("temporal policy package publishes");
    root
}

fn module_bytes(plan: PlanChoice) -> Vec<u8> {
    if matches!(plan, PlanChoice::TemporalSchema) {
        return br#"{"id":"core","version":"1","entities":[{"id":"neutral-record","primaryDataset":"neutral-registry","route":"neutral-records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"], "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}]},{"id":"membership","primaryDataset":"neutral-registry","route":"memberships","mutationMode":"mutable","fields":[{"id":"person","type":"string","maxLength":32,"required":true,"classification":"internal"},{"id":"valid-from","type":"date","required":true,"classification":"internal"},{"id":"valid-to","type":"date","classification":"internal"}],"temporal":{"startField":"valid-from","endField":"valid-to"},"constraints":[{"id":"membership-window","kind":"temporal-non-overlap","scopeFields":["person"],"startField":"valid-from","endField":"valid-to"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["person","valid-from","valid-to"], "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}]}]}"#
            .to_vec();
    }
    let second = if matches!(
        plan,
        PlanChoice::SecondTable | PlanChoice::ThirdTable | PlanChoice::WebhookSecondTable
    ) {
        r#",{"id":"second-record","primaryDataset":"neutral-registry","route":"second-records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"writer","principalClaim":"principal","operations":["get","create"],"readableFields":["code"],"writableFields":["code"], "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}]}"#
    } else {
        ""
    };
    let third = if matches!(plan, PlanChoice::ThirdTable) {
        r#",{"id":"third-record","primaryDataset":"neutral-registry","route":"third-records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}]}"#
    } else {
        ""
    };
    let events = if matches!(
        plan,
        PlanChoice::WebhookSchema | PlanChoice::WebhookSecondTable
    ) {
        r#","hooks":[{"phase":"after","id":"neutral-created-v1","trigger":"created","projection":["code"],"handler":{"kind":"url","destinationId":"neutral-events"}}]"#
    } else {
        ""
    };
    format!(
        r#"{{"id":"core","version":"1","entities":[{{"id":"neutral-record","primaryDataset":"neutral-registry","route":"neutral-records","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":8,"classification":"internal"}}],"accessProfiles":[{{"requiredScopes":"unrestricted","rowBoundaries":"unrestricted", "id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"]}}]{events}}}{second}{third}]}}"#
    )
    .into_bytes()
}

fn derived_module_bytes() -> Vec<u8> {
    br#"{"id":"core","version":"1","entities":[{"id":"neutral-record","primaryDataset":"neutral-registry","route":"neutral-records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":32,"classification":"internal"}],"derived":[{"id":"summary","sql":"sql/summary.sql","key":"id","fields":[{"id":"summary","type":"string","maxLength":64,"classification":"internal"}]}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code","summary"], "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}]}]}"#.to_vec()
}

fn derived_asset_request(sql: &[u8]) -> PackageBuildRequest {
    derived_asset_request_with_module(derived_module_bytes(), sql)
}

fn derived_asset_request_with_module(module_bytes: Vec<u8>, sql: &[u8]) -> PackageBuildRequest {
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let digest = module_digest_with_assets(
        &module,
        &[ModuleAssetSource {
            module: Some("core".to_owned()),
            path: "sql/summary.sql".to_owned(),
            bytes: sql.to_vec(),
        }],
    );
    let mut request = build_request(BuildRequestParts {
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes: project_bytes(&digest),
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    });
    request.modules[0].assets = vec![PackageSourceFile {
        path: "sql/summary.sql".to_owned(),
        bytes: sql.to_vec(),
    }];
    request
}

struct BuildRequestParts<'a> {
    prior_revision: Option<&'a str>,
    schema_fingerprint: String,
    project_bytes: Vec<u8>,
    module_bytes: Vec<u8>,
    migration_plan: PackageMigrationPlanInput,
}

fn build_request(parts: BuildRequestParts<'_>) -> PackageBuildRequest {
    PackageBuildRequest {
        from_package_digest: parts.prior_revision.map(str::to_owned),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: parts.schema_fingerprint,
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: parts.project_bytes,
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.yaml".to_owned(),
            bytes: parts.module_bytes,
            assets: Vec::new(),
        }],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan: parts.migration_plan,
    }
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn legacy_compiler_fixture(source_revision: &str) -> PackageFixture {
    let root = TempRoot::create();
    let module_bytes = module_bytes(PlanChoice::Schema);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let project_bytes =
        project_bytes_with_source_revision(&module_digest(&module), source_revision);
    let mut request = build_request(BuildRequestParts {
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes,
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    });
    request.compiler_source_revision = source_revision.to_owned();
    let prepared = prepare_package(request).expect("legacy compiler fixture prepares");
    prepared
        .publish_to_directory(root.path())
        .expect("legacy compiler fixture publishes");
    PackageFixture { root }
}

fn local_context() -> PackageLoadContext<'static> {
    PackageLoadContext {
        database_initialization_environment: "local",
    }
}

/// The package identity the database ledger records: the digest of the
/// package's sum file.
fn package_digest_of(root: &Path) -> String {
    registry_breg::package::verify_shared_package(root)
        .expect("fixture package envelope verifies")
        .digest()
        .to_owned()
}

async fn ledger_apply_order(database: &TestDatabase, activation_id: &str) -> i64 {
    database
        .admin
        .query_one(
            "SELECT apply_order FROM registry_internal.registry_migrations
             WHERE activation_id = $1::text::uuid",
            &[&activation_id],
        )
        .await
        .expect("the activation has one ledger row")
        .get(0)
}

async fn apply_package(
    database: &TestDatabase,
    package: &registry_breg::package::VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
    lock_timeout: Duration,
    statement_timeout: Duration,
) -> registry_breg::migration::Result<ExpectedRegistryIdentity> {
    let timeouts = ApplyTimeouts::new(lock_timeout, statement_timeout)
        .expect("test apply timeouts are bounded");
    apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        package,
        ActivationDeployment::new("local", INSTANCE, DATABASE),
        precondition,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        timeouts,
        database.activation_audit(),
    ))
    .await
}

async fn apply_package_with_event_destination_compatibility(
    database: &TestDatabase,
    package: &registry_breg::package::VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
    inventory: &EventDestinationCompatibilityInventory,
) -> registry_breg::migration::Result<ExpectedRegistryIdentity> {
    let timeouts = ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(1))
        .expect("test apply timeouts are bounded");
    apply_verified_package(
        ApplyVerifiedPackageRequest::new(
            &database.migration_config,
            package,
            ActivationDeployment::new("local", INSTANCE, DATABASE),
            precondition,
            ApplyRoles::new(&database.migration_role, &database.runtime_role),
            timeouts,
            database.activation_audit(),
        )
        .with_event_destination_compatibility_inventory(inventory),
    )
    .await
}

#[derive(Clone, Copy)]
enum UpgradeDeliveryState {
    Pending,
    Delivered,
    DeadLettered,
    Expired,
}

async fn insert_upgrade_webhook_delivery(
    database: &TestDatabase,
    active: &ExpectedRegistryIdentity,
    event_id: Uuid,
    logical_destination_id: &str,
    binding_digest: &str,
    data_schema: &str,
    state: UpgradeDeliveryState,
) {
    let compiled_delivery_id = "events.neutral-record.neutral-created-v1.webhook";
    let payload = br#"{"code":"old"}"#.as_slice();
    let payload_digest = Sha256::digest(payload).to_vec();
    let retry_delays_ms = vec![1_000_i64, 2_000, 4_000, 8_000];
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_outbox
                 (event_id, event_type, trigger, entity_id, record_reference,
                  record_revision, package_revision, schema_fingerprint, payload,
                  payload_expires_at)
             VALUES ($1, 'neutral-created-v1', 'created', 'neutral-record',
                     'record-reference', 1, $2, $3, $4,
                     transaction_timestamp() + interval '7 days')",
            &[
                &event_id,
                &active.activation_id,
                &active.schema_fingerprint,
                &payload,
            ],
        )
        .await
        .expect("upgrade test outbox row inserts");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_webhook_deliveries
                 (event_id, compiled_delivery_id, handler_kind, logical_destination_id,
                  destination_binding_digest, package_revision, schema_fingerprint,
                  data_schema, classification_ceiling, authentication_profile, delivery_mode,
                  attempt_timeout_ms, initial_backoff_ms, maximum_backoff_ms,
                  exponential_backoff_multiplier, maximum_attempts, retry_delays_ms,
                  maximum_payload_bytes, payload_digest, deployed_attempt_timeout_ms,
                  deployed_maximum_attempts, dead_letter, operator_replay)
             VALUES ($1, $2, 'url', $3, $4, $5, $6, $7, 'internal', 'hmac_sha256_v1',
                     'after_commit', 5000, 1000, 8000, 2, 5, $8, 1024, $9,
                     4000, 4, 'required', true)",
            &[
                &event_id,
                &compiled_delivery_id,
                &logical_destination_id,
                &binding_digest,
                &active.activation_id,
                &active.schema_fingerprint,
                &data_schema,
                &retry_delays_ms,
                &payload_digest,
            ],
        )
        .await
        .expect("upgrade test captured delivery inserts");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_webhook_delivery_state
                 (event_id, compiled_delivery_id, generation, state, attempt, next_attempt_at)
             VALUES ($1, $2, 1, 'pending', 0, transaction_timestamp())",
            &[&event_id, &compiled_delivery_id],
        )
        .await
        .expect("upgrade test pending state inserts");

    let terminal_update = match state {
        UpgradeDeliveryState::Pending => return,
        UpgradeDeliveryState::Delivered => {
            "SET state = 'delivered', attempt = 1, next_attempt_at = NULL,
                 delivered_at = transaction_timestamp(), updated_at = transaction_timestamp()"
        }
        UpgradeDeliveryState::DeadLettered => {
            "SET state = 'dead_lettered', attempt = 1, next_attempt_at = NULL,
                 dead_lettered_at = transaction_timestamp(), updated_at = transaction_timestamp()"
        }
        UpgradeDeliveryState::Expired => {
            "SET state = 'expired', next_attempt_at = NULL,
                 expired_at = transaction_timestamp(), updated_at = transaction_timestamp()"
        }
    };
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_internal.registry_webhook_delivery_state {terminal_update}
                 WHERE event_id = $1 AND compiled_delivery_id = $2"
            ),
            &[&event_id, &compiled_delivery_id],
        )
        .await
        .expect("upgrade test terminal state installs");
    if matches!(
        state,
        UpgradeDeliveryState::Delivered | UpgradeDeliveryState::Expired
    ) {
        database
            .admin
            .execute(
                "UPDATE registry_internal.registry_outbox
                 SET payload = NULL,
                     payload_expires_at = CASE
                         WHEN $2 THEN transaction_timestamp() - interval '1 second'
                         ELSE payload_expires_at
                     END
                 WHERE event_id = $1",
                &[&event_id, &matches!(state, UpgradeDeliveryState::Expired)],
            )
            .await
            .expect("upgrade test terminal payload is erased");
    }
}

struct EventDestinationCompatibilityFixture {
    _root: TempRoot,
    secret_root: PathBuf,
    package_root: PathBuf,
}

impl EventDestinationCompatibilityFixture {
    fn create() -> Self {
        let root = TempRoot::create();
        fs::create_dir(root.path()).expect("destination compatibility root creates");
        let secret_root = root.path().join("secrets");
        let package_root = root.path().join("package");
        fs::create_dir(&secret_root).expect("destination compatibility secrets create");
        fs::create_dir(&package_root).expect("destination compatibility package root creates");
        let key_path = secret_root.join("webhook-key");
        fs::write(&key_path, [0x51_u8; 32]).expect("destination compatibility key writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
                .expect("destination compatibility key permissions set");
        }
        Self {
            _root: root,
            secret_root,
            package_root,
        }
    }

    fn inventory(
        &self,
        registry: &registry_breg::CompiledRegistry,
        path: &str,
    ) -> EventDestinationCompatibilityInventory {
        let audit_path = self
            .secret_root
            .with_file_name("audit")
            .join("audit.jsonl")
            .display()
            .to_string();
        let raw = format!(
            r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:8080
identity:
  environment: local
  instanceId: {INSTANCE}
  databaseId: {DATABASE}
  databaseInitializationEnvironment: local
secretProviders:
  file:
    root: {}
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 4
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: registry_migration
    runtime: registry_runtime
package:
  root: {}
authentication:
  oidc:
    issuer: https://issuer.example
    audience: urn:breg:webhook-upgrade
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [registry-client]
    deniedKids: [denied-kid]
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 900
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit:
  hashKeyRef: secret:file/audit-key
  path: {audit_path}
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
eventDestinations:
  neutral-events:
    origin: https://events.example/
    path: {path}
    networkProfile: productionHttps
    dnsFamily: dualStackStrict
    allowedPrivateCidrs: []
    hmacSha256KeyRef: secret:file/webhook-key
    classificationCeiling: internal
    deliveryCeilings:
      attemptTimeoutMilliseconds: 4000
      maximumAttempts: 4
operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 30000
  migrationStatementMilliseconds: 60000
"#,
            self.secret_root.display(),
            self.package_root.display(),
        );
        parse_runtime_config(&raw)
            .expect("upgrade compatibility runtime parses")
            .activate_event_destinations(registry)
            .expect("upgrade compatibility destination activates")
            .compatibility_inventory()
    }
}

async fn registry_state_snapshot(
    client: &impl GenericClient,
) -> (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
) {
    let row = client
        .query_one(
            "SELECT package_id, database_id, active_package_digest,
                    active_activation_id::text, schema_fingerprint,
                    maintenance_status, maintenance_target_package_digest
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await
        .expect("Registry state snapshot reads");
    (
        row.get(0),
        row.get(1),
        row.get(2),
        row.get(3),
        row.get(4),
        row.get(5),
        row.get(6),
    )
}

async fn migration_ledger_snapshot(
    client: &impl GenericClient,
) -> Vec<(
    Option<String>,
    String,
    i64,
    Vec<String>,
    String,
    String,
    Option<String>,
)> {
    client
        .query(
            "SELECT predecessor_package_digest, package_digest, apply_order,
                    statement_checksums, outcome, started_at::text, completed_at::text
             FROM registry_internal.registry_migrations
             ORDER BY apply_order",
            &[],
        )
        .await
        .expect("migration ledger snapshot reads")
        .into_iter()
        .map(|row| {
            (
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
                row.get(6),
            )
        })
        .collect()
}

async fn wait_for_maintenance_status(client: &impl GenericClient, expected: &str) {
    for _ in 0..200 {
        let status: Option<String> = client
            .query_opt(
                "SELECT maintenance_status
                 FROM registry_internal.registry_state
                 WHERE singleton",
                &[],
            )
            .await
            .expect("maintenance polling remains available")
            .map(|row| row.get(0));
        if status.as_deref() == Some(expected) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("maintenance state did not reach the expected value");
}

async fn wait_for_blocked_apply_backend(
    client: &impl GenericClient,
    migration_role: &str,
    excluded_pid: i32,
) -> i32 {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let rows = client
                .query(
                    "SELECT pid
                     FROM pg_stat_activity
                     WHERE datname = current_database()
                       AND usename = $1
                       AND pid <> $2
                       AND backend_type = 'client backend'
                       AND wait_event_type = 'Lock'",
                    &[&migration_role, &excluded_pid],
                )
                .await
                .expect("administrator observes blocked database sessions");
            if let [row] = rows.as_slice() {
                return row.get(0);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the dedicated apply backend reaches its deterministic DDL wait")
}

fn rewrite_temporal_metadata(root: &Path, add_scope_fields: bool, mutate: impl Fn(&mut Value)) {
    let mut effective_model: Value =
        serde_json::from_slice(&fs::read(governed_model_path(root)).expect("governed model reads"))
            .expect("governed model parses");
    if add_scope_fields {
        let membership = effective_model["entities"]["membership"]
            .as_object_mut()
            .expect("membership entity exists");
        membership["temporal"]
            .as_object_mut()
            .expect("membership temporal exists")
            .insert("scopeFields".to_owned(), json!(["person"]));
    }
    mutate_temporal_query_bindings(
        effective_model
            .get_mut("queryInventory")
            .expect("effective model query inventory exists"),
        add_scope_fields,
        &mutate,
    );
    let effective_model_bytes = canonicalize_json(&effective_model).expect("model canonicalizes");

    let query_inventory_path = manifest_file_path(root, PackageFileRole::QueryInventory);
    let mut query_inventory: Value =
        serde_json::from_slice(&fs::read(&query_inventory_path).expect("query inventory reads"))
            .expect("query inventory parses");
    mutate_temporal_query_bindings(&mut query_inventory, add_scope_fields, &mutate);
    let query_inventory_bytes =
        canonicalize_json(&query_inventory).expect("query inventory canonicalizes");

    write_signed_files(
        root,
        [
            ("effective-model.json", effective_model_bytes),
            ("inventories/queries.json", query_inventory_bytes),
        ],
    );
}

fn mutate_temporal_query_bindings(
    query_inventory: &mut Value,
    add_scope_fields: bool,
    mutate: &impl Fn(&mut Value),
) {
    for operation in query_inventory
        .get_mut("operations")
        .and_then(Value::as_array_mut)
        .expect("query operations exist")
    {
        if let Some(temporal) = operation
            .as_object_mut()
            .expect("query operation is an object")
            .get_mut("temporal")
        {
            if add_scope_fields {
                temporal
                    .as_object_mut()
                    .expect("temporal binding is an object")
                    .insert("scopeFields".to_owned(), json!(["person"]));
            }
            mutate(temporal);
        }
    }
}

fn write_signed_files<const N: usize>(root: &Path, files: [(&str, Vec<u8>); N]) {
    let mut envelope = read_envelope(root);
    for (relative, bytes) in files {
        fs::write(root.join(relative), &bytes).expect("signed file writes");
        let entry = envelope
            .manifest
            .files
            .iter_mut()
            .find(|entry| entry.path == relative)
            .expect("signed file entry exists");
        entry.size = bytes.len() as u64;
        entry.sha256 = format!("sha256:{}", hex(&Sha256::digest(&bytes)));
    }
    write_json(&root.join("package.json"), &envelope);
    refresh_shared_package_envelope(root);
}

fn rewrite_unsigned(root: &Path, mutate: impl FnOnce(&mut PackageManifest)) {
    let mut envelope = read_envelope(root);
    mutate(&mut envelope.manifest);
    let migration_plan_bytes = canonicalize_json(
        &serde_json::to_value(&envelope.manifest.migration_plan).expect("value serializes"),
    )
    .expect("value canonicalizes");
    let migration_plan_path = root.join("database/migration-plan.json");
    if migration_plan_path.is_file() {
        fs::write(&migration_plan_path, &migration_plan_bytes).expect("migration plan file writes");
        if let Some(entry) = envelope
            .manifest
            .files
            .iter_mut()
            .find(|entry| entry.path == "database/migration-plan.json")
        {
            entry.size = migration_plan_bytes.len() as u64;
            entry.sha256 = format!("sha256:{}", hex(&Sha256::digest(&migration_plan_bytes)));
        }
    }
    write_json(&root.join("package.json"), &envelope);
    refresh_shared_package_envelope(root);
}

fn rewrite_envelope(root: &Path, mutate: impl FnOnce(&mut PackageEnvelope)) {
    let mut envelope = read_envelope(root);
    mutate(&mut envelope);
    write_json(&root.join("package.json"), &envelope);
    refresh_shared_package_envelope(root);
}

/// Reduce a package to the layout a `bregctl` release before the shared
/// package format wrote: the signed manifest and its files, with no
/// `SHA256SUMS` or `REVISION`.
fn strip_shared_package_envelope(root: &Path) {
    fs::remove_file(root.join(SUM_FILE)).expect("shared package checksum file removes");
    let revision = root.join(REVISION_FILE);
    if revision.exists() {
        fs::remove_file(revision).expect("shared package revision file removes");
    }
}

fn refresh_shared_package_envelope(root: &Path) {
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

fn read_envelope(root: &Path) -> PackageEnvelope {
    serde_json::from_slice(&fs::read(root.join("package.json")).expect("manifest reads"))
        .expect("manifest parses")
}

fn write_json(path: &Path, value: &impl Serialize) {
    let bytes = canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes");
    write_file(path, &bytes);
}

fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent directories create");
    }
    fs::write(path, bytes).expect("fixture file writes");
}

fn first_generated_path(root: &Path) -> PathBuf {
    let envelope = read_envelope(root);
    root.join(
        &envelope
            .manifest
            .files
            .iter()
            .find(|entry| entry.role == PackageFileRole::GeneratedOpenapi)
            .expect("generated entry exists")
            .path,
    )
}

fn manifest_projection_path(root: &Path) -> PathBuf {
    let envelope = read_envelope(root);
    root.join(
        &envelope
            .manifest
            .files
            .iter()
            .find(|entry| entry.role == PackageFileRole::LossyManifestProjection)
            .expect("Manifest projection entry exists")
            .path,
    )
}

fn governed_model_path(root: &Path) -> PathBuf {
    let envelope = read_envelope(root);
    root.join(
        &envelope
            .manifest
            .files
            .iter()
            .find(|entry| entry.role == PackageFileRole::GovernedModel)
            .expect("governed model entry exists")
            .path,
    )
}

fn manifest_file_path(root: &Path, role: PackageFileRole) -> PathBuf {
    let envelope = read_envelope(root);
    root.join(
        &envelope
            .manifest
            .files
            .iter()
            .find(|entry| entry.role == role)
            .expect("manifest file entry exists")
            .path,
    )
}

fn load_error(root: &Path, context: &PackageLoadContext<'_>) -> PackageError {
    load_package(root, context)
        .err()
        .expect("package is refused")
}

fn predecessor_load_error(root: &Path, context: &PackageLoadContext<'_>) -> PackageError {
    load_predecessor_package(root, context)
        .err()
        .expect("predecessor package is refused")
}

fn fingerprint(byte: u8) -> String {
    format!("sha256:{}", format!("{byte:02x}").repeat(32))
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String succeeds");
    }
    result
}
