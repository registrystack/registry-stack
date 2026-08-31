// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

#[path = "support/postgres_harness.rs"]
mod postgres_harness;

#[path = "postgres_package/fingerprint.rs"]
mod fingerprint_tests;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use postgres_harness::TestDatabase;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use registry_server::compiler::{
    compile_project, module_digest, module_digest_with_assets, CompileProfile,
};
use registry_server::contract::{parse_module_yaml, parse_project_yaml, ModuleAssetSource};
use registry_server::event_destination::EventDestinationCompatibilityInventory;
use registry_server::migration::{
    apply_verified_package, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest, MigrationError,
};
use registry_server::package::{
    derive_package_revision, load_package, prepare_package, PackageBuildRequest, PackageEnvelope,
    PackageError, PackageFile, PackageFileRole, PackageIntent, PackageLoadContext, PackageManifest,
    PackageMigrationPlanInput, PackageModuleSource, PackageSignature, PackageSourceFile,
    PackageTrustAnchor, SignaturePolicy, TrustAnchorKey, MAX_PACKAGE_SOURCE_FILE_BYTES,
    TRUST_ANCHOR_API_VERSION,
};
use registry_server::postgres::{
    begin_record_transaction, install_compiled_schema, managed_schema_fingerprint, ClaimContext,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, RegistryLockKey,
};
use registry_server::runtime_config::parse_runtime_config;
use registry_server::startup::{prepare_startup, StartupError};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio_postgres::GenericClient;
use uuid::Uuid;

const INSTANCE: &str = "instance-under-test";
const DATABASE: &str = "database-under-test";
const SOURCE_REVISION: &str = "compiler-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: package-read
    steps:
      - id: list-neutral-records
        entity: neutral-record
        accessProfile: reader
        claims: {principal: package-reader}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn package_builder_is_deterministic_and_local_publication_loads() {
    let module_bytes = module_bytes(PlanChoice::Schema);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let project_bytes = project_bytes("local", 1, &module_digest(&module));
    let request = build_request(BuildRequestParts {
        environment: "local",
        sequence: 1,
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes,
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
    });
    let first = prepare_package(request.clone()).expect("first package prepares");
    let second = prepare_package(request).expect("second package prepares");
    assert_eq!(first.manifest(), second.manifest());
    assert_eq!(
        first.canonical_signed_bytes(),
        second.canonical_signed_bytes()
    );
    assert_eq!(first.file_bytes(), second.file_bytes());
    assert_eq!(first.registry(), second.registry());

    let root = TempRoot::create();
    first
        .publish_to_directory(root.path(), Vec::new())
        .expect("local package publishes");
    load_package(
        root.path(),
        &local_context(PackageIntent::InitialActivation),
    )
    .expect("published local package loads");
    assert_eq!(
        first
            .publish_to_directory(root.path(), Vec::new())
            .expect_err("package publication refuses replacement"),
        PackageError::Closure
    );
}

#[test]
fn package_builder_refuses_successor_without_prior_compiled_registry() {
    let module_bytes = module_bytes(PlanChoice::SecondTable);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let project_bytes = project_bytes("local", 2, &module_digest(&module));
    let refused = prepare_package(build_request(BuildRequestParts {
        environment: "local",
        sequence: 2,
        prior_revision: Some(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        ),
        schema_fingerprint: fingerprint(1),
        project_bytes,
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
    }));
    assert_eq!(refused.err(), Some(PackageError::MigrationPlan));
}

#[test]
fn package_layout_contract_conditional_manifest_projection_is_in_projected_closure() {
    let layout = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/registry-server/contracts/package-layout.yaml"
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
    let project_bytes = project_bytes("local", 1, &module_digest(&module));
    let package = prepare_package(build_request(BuildRequestParts {
        environment: "local",
        sequence: 1,
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes,
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
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
    let project_bytes = project_bytes_without_manifest("local", 1, &module_digest(&module));
    let request = build_request(BuildRequestParts {
        environment: "local",
        sequence: 1,
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes,
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
    });

    let first = prepare_package(request.clone()).expect("projection-free package prepares");
    let second = prepare_package(request).expect("projection-free package prepares again");
    assert_eq!(first.manifest(), second.manifest());
    assert_eq!(
        first.canonical_signed_bytes(),
        second.canonical_signed_bytes()
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
        .publish_to_directory(root.path(), Vec::new())
        .expect("projection-free package publishes");
    let loaded = load_package(
        root.path(),
        &local_context(PackageIntent::InitialActivation),
    )
    .expect("projection-free package loads through full closure rederivation");
    assert!(loaded.registry().manifest_projection().is_none());
}

#[test]
fn projection_free_package_refuses_claimed_manifest_artifacts() {
    let module_bytes = module_bytes(PlanChoice::Schema);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let package = prepare_package(build_request(BuildRequestParts {
        environment: "local",
        sequence: 1,
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes: project_bytes_without_manifest("local", 1, &module_digest(&module)),
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
    }))
    .expect("projection-free package prepares");
    let root = TempRoot::create();
    package
        .publish_to_directory(root.path(), Vec::new())
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
        load_error(
            root.path(),
            &local_context(PackageIntent::InitialActivation),
        ),
        PackageError::Derivation
    );
}

#[test]
fn fixture_journeys_are_required_at_the_fixed_path_and_change_the_package_revision() {
    let module_bytes = module_bytes(PlanChoice::Schema);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let project_bytes = project_bytes("local", 1, &module_digest(&module));
    let request = build_request(BuildRequestParts {
        environment: "local",
        sequence: 1,
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes,
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
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
    assert_ne!(first.package_revision(), second.package_revision());
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
    assert_ne!(first.package_revision(), second.package_revision());
}

#[test]
fn derived_sql_asset_tampering_is_refused_before_activation() {
    let prepared = prepare_package(derived_asset_request(
        b"SELECT r.id AS id, r.code AS summary FROM registry_source.neutral_record r",
    ))
    .expect("derived package prepares");
    let root = TempRoot::create();
    prepared
        .publish_to_directory(root.path(), Vec::new())
        .expect("package publishes");
    let context = local_context(PackageIntent::InitialActivation);
    load_package(root.path(), &context).expect("untampered asset package loads");

    let asset_path = root.path().join("source/modules/core/sql/summary.sql");
    let original = fs::read(&asset_path).expect("asset reads");
    fs::write(
        &asset_path,
        b"SELECT r.id AS id, (r.code) AS summary FROM registry_source.neutral_record r",
    )
    .expect("asset tamper writes");
    assert_eq!(load_error(root.path(), &context), PackageError::Integrity);
    fs::write(&asset_path, original).expect("asset restores");

    fs::remove_file(&asset_path).expect("asset removes");
    assert!(matches!(
        load_error(root.path(), &context),
        PackageError::Read | PackageError::Closure
    ));
}

#[test]
fn derived_sql_asset_extra_path_swap_and_size_are_refused() {
    let prepared = prepare_package(derived_asset_request(
        b"SELECT r.id AS id, r.code AS summary FROM registry_source.neutral_record r",
    ))
    .expect("derived package prepares");
    let root = TempRoot::create();
    prepared
        .publish_to_directory(root.path(), Vec::new())
        .expect("package publishes");
    let context = local_context(PackageIntent::InitialActivation);

    fs::write(
        root.path().join("source/modules/core/sql/unlisted.sql"),
        b"SELECT r.id AS id, r.code AS summary FROM registry_source.neutral_record r",
    )
    .expect("extra asset writes");
    assert_eq!(load_error(root.path(), &context), PackageError::Closure);
    fs::remove_file(root.path().join("source/modules/core/sql/unlisted.sql"))
        .expect("extra asset removes");

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
    oversized.project.bytes = project_bytes(
        "local",
        1,
        &module_digest_with_assets(
            &module,
            &[ModuleAssetSource {
                module: Some("core".to_owned()),
                path: "sql/summary.sql".to_owned(),
                bytes,
            }],
        ),
    );
    assert_eq!(
        prepare_package(oversized).err(),
        Some(PackageError::Derivation)
    );
}

#[test]
fn signed_package_refuses_missing_or_rehashed_substituted_fixture_journeys() {
    let signing =
        generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("package signing key generates");

    let missing = PackageFixture::build(
        "production",
        1,
        None,
        fingerprint(1),
        PlanChoice::Schema,
        Some(&signing),
    );
    fs::remove_file(missing.root.path().join("tests/journeys.yaml"))
        .expect("fixture journeys remove");
    assert_eq!(
        load_error(
            missing.root.path(),
            &missing.context(PackageIntent::InitialActivation),
        ),
        PackageError::Read
    );

    let substituted = PackageFixture::build(
        "production",
        1,
        None,
        fingerprint(1),
        PlanChoice::Schema,
        Some(&signing),
    );
    let replacement = [FIXTURE_JOURNEYS, b"\n"].concat();
    fs::write(
        substituted.root.path().join("tests/journeys.yaml"),
        &replacement,
    )
    .expect("fixture journeys substitution writes");
    rewrite_envelope(substituted.root.path(), |envelope| {
        let entry = envelope
            .signed
            .files
            .iter_mut()
            .find(|entry| entry.role == PackageFileRole::FixtureJourneys)
            .expect("fixture journey entry exists");
        entry.size = replacement.len() as u64;
        entry.sha256 = format!("sha256:{}", hex(&Sha256::digest(&replacement)));
        envelope.signed.package_revision.clear();
        envelope.signed.package_revision =
            derive_package_revision(&envelope.signed).expect("substituted revision derives");
    });
    assert_eq!(
        load_error(
            substituted.root.path(),
            &substituted.context(PackageIntent::InitialActivation),
        ),
        PackageError::Signature
    );
}

#[test]
fn package_rederivation_refuses_a_rehashed_fixture_journey_role_substitution() {
    let fixture = PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    rewrite_unsigned(fixture.root.path(), |manifest| {
        manifest
            .files
            .iter_mut()
            .find(|entry| entry.path == "tests/journeys.yaml")
            .expect("fixture journey entry exists")
            .role = PackageFileRole::SourceModule;
    });

    assert_eq!(
        load_error(
            fixture.root.path(),
            &local_context(PackageIntent::InitialActivation),
        ),
        PackageError::Derivation
    );
}

#[test]
fn package_rederivation_refuses_rehashed_empty_fixture_journeys() {
    let fixture = PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
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
        load_error(
            fixture.root.path(),
            &local_context(PackageIntent::InitialActivation),
        ),
        PackageError::Derivation
    );
}

#[test]
fn package_rederivation_refuses_rehashed_substituted_caller_safe_metadata() {
    let fixture = PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
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
        load_error(
            fixture.root.path(),
            &local_context(PackageIntent::InitialActivation),
        ),
        PackageError::Derivation
    );
}

#[test]
fn package_rederivation_refuses_a_rehashed_substituted_event_inventory() {
    let fixture = PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
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
        load_error(
            fixture.root.path(),
            &local_context(PackageIntent::InitialActivation),
        ),
        PackageError::Derivation
    );
}

#[test]
fn local_unsigned_package_rederives_every_artifact_and_refuses_filesystem_tampering() {
    let fixture = PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    let context = local_context(PackageIntent::InitialActivation);
    let verified =
        load_package(fixture.root.path(), &context).expect("local unsigned package verifies");
    assert_eq!(verified.manifest().package_id, "neutral-registry");
    assert_eq!(verified.registry().registry_id(), "neutral-registry");

    let artifact_path = first_generated_path(fixture.root.path());
    let original = fs::read(&artifact_path).expect("artifact reads");
    fs::write(&artifact_path, b"tampered artifact").expect("artifact tamper writes");
    assert_eq!(
        load_error(fixture.root.path(), &context),
        PackageError::Integrity
    );
    fs::write(&artifact_path, original).expect("artifact restores");

    let manifest_projection_path = manifest_projection_path(fixture.root.path());
    let original_manifest_projection_bytes =
        fs::read(&manifest_projection_path).expect("Manifest projection reads");
    let original_manifest_projection_entry = read_envelope(fixture.root.path())
        .signed
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
    assert_eq!(
        load_error(fixture.root.path(), &context),
        PackageError::Integrity
    );
    fs::write(&source, original).expect("source restores");

    let module = fixture.root.path().join("source/modules/core/module.yaml");
    let original = fs::read(&module).expect("module reads");
    fs::write(&module, b"tampered module").expect("module tamper writes");
    assert_eq!(
        load_error(fixture.root.path(), &context),
        PackageError::Integrity
    );
    fs::write(&module, original).expect("module restores");

    fs::write(fixture.root.path().join("unlisted"), b"unlisted").expect("unlisted file writes");
    assert_eq!(
        load_error(fixture.root.path(), &context),
        PackageError::Closure
    );
    fs::remove_file(fixture.root.path().join("unlisted")).expect("unlisted file removes");

    fs::remove_file(&artifact_path).expect("listed artifact removes");
    assert!(matches!(
        load_error(fixture.root.path(), &context),
        PackageError::Read | PackageError::Closure
    ));
}

#[test]
fn package_manifest_refuses_ddl_checksum_path_and_canonical_json_tampering() {
    let context = local_context(PackageIntent::InitialActivation);

    let ddl = PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    rewrite_unsigned(ddl.root.path(), |manifest| {
        manifest.migration_plan.statements[0]
            .sql
            .push_str(" SELECT 1");
    });
    assert_eq!(
        load_error(ddl.root.path(), &context),
        PackageError::MigrationPlan
    );

    let checksum =
        PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    rewrite_unsigned(checksum.root.path(), |manifest| {
        manifest.files[0].sha256 = fingerprint(9);
    });
    assert_eq!(
        load_error(checksum.root.path(), &context),
        PackageError::Integrity
    );

    let duplicate =
        PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    rewrite_unsigned(duplicate.root.path(), |manifest| {
        manifest.files.insert(0, manifest.files[0].clone());
    });
    assert_eq!(
        load_error(duplicate.root.path(), &context),
        PackageError::Closure
    );

    let traversal =
        PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    rewrite_unsigned(traversal.root.path(), |manifest| {
        manifest.files[0].path = "../outside".to_owned();
    });
    assert_eq!(
        load_error(traversal.root.path(), &context),
        PackageError::UnsafePath
    );

    let absolute =
        PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    rewrite_unsigned(absolute.root.path(), |manifest| {
        manifest.files[0].path = "/absolute".to_owned();
    });
    assert_eq!(
        load_error(absolute.root.path(), &context),
        PackageError::UnsafePath
    );

    let noncanonical_path =
        PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    rewrite_unsigned(noncanonical_path.root.path(), |manifest| {
        manifest.files[0].path = "source//registry.yaml".to_owned();
    });
    assert_eq!(
        load_error(noncanonical_path.root.path(), &context),
        PackageError::UnsafePath
    );

    let nonregular =
        PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    let path = first_generated_path(nonregular.root.path());
    fs::remove_file(&path).expect("listed file removes");
    fs::create_dir(&path).expect("non-regular replacement creates");
    assert_eq!(
        load_error(nonregular.root.path(), &context),
        PackageError::Closure
    );

    let noncanonical =
        PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    let path = noncanonical.root.path().join("package.json");
    let mut bytes = fs::read(&path).expect("manifest reads");
    bytes.push(b'\n');
    fs::write(&path, bytes).expect("noncanonical manifest writes");
    assert_eq!(
        load_error(noncanonical.root.path(), &context),
        PackageError::CanonicalJson
    );
}

#[test]
fn successor_migration_plan_rederivation_rejects_tampered_closure() {
    let first = PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    let prior_revision = read_envelope(first.root.path()).signed.package_revision;
    let context = local_context(PackageIntent::Activation {
        active_revision: &prior_revision,
        active_sequence: 1,
    });
    let build_successor = || {
        PackageFixture::build(
            "local",
            2,
            Some(&prior_revision),
            fingerprint(1),
            PlanChoice::SecondTable,
            None,
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
            .map(|baseline| baseline.package_revision.as_str()),
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
            .package_revision = fingerprint(9);
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

    let local = PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    let artifact = first_generated_path(local.root.path());
    let target = local.root.path().join("ordinary-target");
    fs::write(&target, fs::read(&artifact).expect("artifact reads")).expect("target writes");
    fs::remove_file(&artifact).expect("artifact removes");
    symlink(&target, &artifact).expect("test symlink creates");
    let context = local_context(PackageIntent::InitialActivation);
    assert_eq!(
        load_error(local.root.path(), &context),
        PackageError::UnsafePath
    );

    let signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("test key generates");
    let production = PackageFixture::build(
        "production",
        1,
        None,
        fingerprint(1),
        PlanChoice::Schema,
        Some(&signing),
    );
    fs::set_permissions(production.root.path(), fs::Permissions::from_mode(0o777))
        .expect("test permissions change");
    let context = production.context(PackageIntent::InitialActivation);
    assert_eq!(
        load_error(production.root.path(), &context),
        PackageError::Permissions
    );

    let anchor_permissions = PackageFixture::build(
        "production",
        1,
        None,
        fingerprint(1),
        PlanChoice::Schema,
        Some(&signing),
    );
    fs::set_permissions(
        anchor_permissions
            .anchor
            .as_deref()
            .expect("production fixture has anchor"),
        fs::Permissions::from_mode(0o666),
    )
    .expect("test anchor permissions change");
    assert_eq!(
        load_error(
            anchor_permissions.root.path(),
            &anchor_permissions.context(PackageIntent::InitialActivation)
        ),
        PackageError::Permissions
    );
}

#[test]
fn package_binding_refuses_wrong_environment_instance_database_sequence_and_prior() {
    let fixture = PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    let wrong_environment = PackageLoadContext {
        environment: "production",
        ..local_context(PackageIntent::InitialActivation)
    };
    assert_eq!(
        load_error(fixture.root.path(), &wrong_environment),
        PackageError::Binding
    );
    let wrong_instance = PackageLoadContext {
        instance_id: "another-instance",
        ..local_context(PackageIntent::InitialActivation)
    };
    assert_eq!(
        load_error(fixture.root.path(), &wrong_instance),
        PackageError::Binding
    );
    let wrong_database = PackageLoadContext {
        database_id: "another-database",
        ..local_context(PackageIntent::InitialActivation)
    };
    assert_eq!(
        load_error(fixture.root.path(), &wrong_database),
        PackageError::Binding
    );

    let sequence =
        PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    rewrite_unsigned(sequence.root.path(), |manifest| {
        manifest.sequence = 2;
    });
    assert_eq!(
        load_error(
            sequence.root.path(),
            &local_context(PackageIntent::InitialActivation)
        ),
        PackageError::Binding
    );

    let successor = PackageFixture::build(
        "local",
        2,
        Some("expected-prior"),
        fingerprint(1),
        PlanChoice::Schema,
        None,
    );
    let wrong_prior = local_context(PackageIntent::Activation {
        active_revision: "other-prior",
        active_sequence: 1,
    });
    assert_eq!(
        load_error(successor.root.path(), &wrong_prior),
        PackageError::Binding
    );
    let stale = local_context(PackageIntent::Activation {
        active_revision: "expected-prior",
        active_sequence: 2,
    });
    assert_eq!(
        load_error(successor.root.path(), &stale),
        PackageError::Binding
    );
}

#[test]
fn production_package_requires_exact_trust_anchor_threshold_and_signature() {
    let signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("test key generates");
    let fixture = PackageFixture::build(
        "production",
        1,
        None,
        fingerprint(1),
        PlanChoice::Schema,
        Some(&signing),
    );
    let context = fixture.context(PackageIntent::InitialActivation);
    load_package(fixture.root.path(), &context).expect("production-shaped signed package verifies");

    let missing_anchor = PackageLoadContext {
        trust_anchor: None,
        ..fixture.context(PackageIntent::InitialActivation)
    };
    assert_eq!(
        load_error(fixture.root.path(), &missing_anchor),
        PackageError::Signature
    );

    rewrite_envelope(fixture.root.path(), |envelope| {
        let byte_length = envelope.signatures[0].signature_hex.len() / 2;
        envelope.signatures[0].signature_hex = "00".repeat(byte_length);
    });
    assert_eq!(
        load_error(fixture.root.path(), &context),
        PackageError::Signature
    );

    let insufficient = PackageFixture::build(
        "production",
        1,
        None,
        fingerprint(1),
        PlanChoice::Schema,
        Some(&signing),
    );
    rewrite_envelope(insufficient.root.path(), |envelope| {
        envelope.signatures.clear();
    });
    assert_eq!(
        load_error(
            insufficient.root.path(),
            &insufficient.context(PackageIntent::InitialActivation)
        ),
        PackageError::Signature
    );

    let duplicate = PackageFixture::build(
        "production",
        1,
        None,
        fingerprint(1),
        PlanChoice::Schema,
        Some(&signing),
    );
    rewrite_envelope(duplicate.root.path(), |envelope| {
        envelope.signatures.push(envelope.signatures[0].clone());
    });
    assert_eq!(
        load_error(
            duplicate.root.path(),
            &duplicate.context(PackageIntent::InitialActivation)
        ),
        PackageError::Signature
    );

    let untrusted = PackageFixture::build(
        "production",
        1,
        None,
        fingerprint(1),
        PlanChoice::Schema,
        Some(&signing),
    );
    rewrite_envelope(untrusted.root.path(), |envelope| {
        envelope.signatures[0].key_id = "untrusted-key".to_owned();
    });
    assert_eq!(
        load_error(
            untrusted.root.path(),
            &untrusted.context(PackageIntent::InitialActivation)
        ),
        PackageError::Signature
    );

    let local_runtime = PackageLoadContext {
        environment: "local",
        ..untrusted.context(PackageIntent::InitialActivation)
    };
    assert_eq!(
        load_error(untrusted.root.path(), &local_runtime),
        PackageError::Binding
    );
}

#[test]
fn package_file_count_and_size_are_bounded_before_payload_reads() {
    let oversized =
        PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    rewrite_unsigned(oversized.root.path(), |manifest| {
        manifest.files[0].size = 16 * 1024 * 1024 + 1;
    });
    assert_eq!(
        load_error(
            oversized.root.path(),
            &local_context(PackageIntent::InitialActivation)
        ),
        PackageError::Closure
    );

    let excessive_count =
        PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
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
        load_error(
            excessive_count.root.path(),
            &local_context(PackageIntent::InitialActivation)
        ),
        PackageError::Integrity
    );
}

#[test]
fn package_apply_and_startup_errors_are_closed_and_value_free() {
    let rendered = format!(
        "{:?} {:?} {:?}",
        PackageError::Signature,
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
    let fixture = PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    let package = load_package(
        fixture.root.path(),
        &local_context(PackageIntent::InitialActivation),
    )
    .expect("initial package verifies before role enforcement");
    let refused = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.runtime_config,
        &package,
        ApplyPrecondition::InitialActivation,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(1))
            .expect("test apply timeouts are bounded"),
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
    let signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384)
        .expect("production-shaped signing key generates");
    let fixture = PackageFixture::build(
        "production",
        1,
        None,
        fingerprint(7),
        PlanChoice::Schema,
        Some(&signing),
    );
    assert_eq!(read_envelope(fixture.root.path()).signatures.len(), 1);
    let initial_context = fixture.context(PackageIntent::InitialActivation);
    let package = load_package(fixture.root.path(), &initial_context)
        .expect("signed production-shaped package verifies before catalog apply");
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
    assert_eq!(state.7, "failed");
    assert_eq!(
        state.8.as_deref(),
        Some(package.manifest().package_revision.as_str())
    );
    let ledger = migration_ledger_snapshot(&database.admin).await;
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger[0].0, None);
    assert_eq!(ledger[0].1, package.manifest().package_revision);
    assert_eq!(ledger[0].4, "failed");

    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool.get_for_test().await.expect("runtime connects");
    let startup_context = fixture.context(PackageIntent::Startup {
        active_revision: &package.manifest().package_revision,
        active_sequence: 1,
    });
    let startup = prepare_startup(
        fixture.root.path(),
        &startup_context,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await;
    assert_eq!(startup.err(), Some(StartupError::DatabaseUnready));
    drop(runtime);
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
    let first = PackageFixture::build("local", 1, None, fingerprint(1), PlanChoice::Schema, None);
    let first_for_install = load_package(
        first.root.path(),
        &local_context(PackageIntent::InitialActivation),
    )
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
    let first_for_state = load_package(
        first.root.path(),
        &local_context(PackageIntent::InitialActivation),
    )
    .expect("initial package reloads after finalized schema fingerprint");
    let first_manifest = first_for_state.manifest().clone();
    let successor_before_initialization = PackageFixture::build(
        "local",
        2,
        Some(&first_manifest.package_revision),
        schema.clone(),
        PlanChoice::Schema,
        None,
    );
    let successor_before_initialization_context = local_context(PackageIntent::Activation {
        active_revision: &first_manifest.package_revision,
        active_sequence: 1,
    });
    let verified_successor_before_initialization = load_package(
        successor_before_initialization.root.path(),
        &successor_before_initialization_context,
    )
    .expect("successor package verifies for activation before database initialization");
    assert_eq!(
        verified_successor_before_initialization
            .manifest()
            .schema_fingerprint,
        schema
    );
    let refused_successor_initialization = apply_package(
        &database,
        &verified_successor_before_initialization,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(
        refused_successor_initialization.err(),
        Some(MigrationError::PackageBinding)
    );
    let wrong_migration_role = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.runtime_config,
        &first_for_state,
        ApplyPrecondition::InitialActivation,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(1))
            .expect("test apply timeouts are bounded"),
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
    let first_startup = local_context(PackageIntent::Startup {
        active_revision: &first_manifest.package_revision,
        active_sequence: 1,
    });
    prepare_startup(
        first.root.path(),
        &first_startup,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("matching package produces the listener gate");
    drop(runtime);
    for (column, original) in [
        ("package_id", initial.package_id.as_str()),
        ("instance_id", initial.instance_id.as_str()),
        ("database_id", initial.database_id.as_str()),
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
            &mut runtime,
            &database.migration_role,
            &database.runtime_role,
        )
        .await;
        assert_eq!(
            refused.err(),
            Some(StartupError::DatabaseUnready),
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

    let tampered_startup =
        PackageFixture::build("local", 1, None, schema.clone(), PlanChoice::Schema, None);
    let tampered_artifact = first_generated_path(tampered_startup.root.path());
    fs::write(tampered_artifact, b"pre-listener tamper").expect("startup artifact tamper writes");
    let mut runtime = pool.get_for_test().await.expect("runtime reconnects");
    let no_listener_gate = prepare_startup(
        tampered_startup.root.path(),
        &first_startup,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await;
    assert_eq!(no_listener_gate.err(), Some(StartupError::PackageRefused));
    drop(runtime);

    let second = PackageFixture::build(
        "local",
        2,
        Some(&first_manifest.package_revision),
        schema.clone(),
        PlanChoice::SecondTable,
        None,
    );
    let activation_context = local_context(PackageIntent::Activation {
        active_revision: &first_manifest.package_revision,
        active_sequence: 1,
    });
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
        Err(registry_server::postgres::PostgresKernelError::RegistryUnavailable) => {}
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
            "SELECT maintenance_status, active_package_revision
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await
        .expect("blocked apply leaves state readable");
    assert_eq!(blocked_state.get::<_, String>(0), "ready");
    assert_eq!(blocked_state.get::<_, String>(1), initial.package_revision);
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
        verified_second.manifest().package_revision.as_str(),
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
    assert_eq!(interrupted_state.4, initial.package_revision);
    assert_eq!(interrupted_state.7, "applying");
    assert_eq!(
        interrupted_state.8.as_deref(),
        Some(verified_second.manifest().package_revision.as_str())
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
            Err(registry_server::postgres::PostgresKernelError::RegistryUnavailable) => {}
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
    assert_eq!(
        active.package_revision,
        verified_second.manifest().package_revision
    );
    let activated_state = registry_state_snapshot(&database.admin).await;
    assert_eq!(activated_state.0, active.package_id);
    assert_eq!(activated_state.2, active.instance_id);
    assert_eq!(activated_state.3, active.database_id);
    let applied_ledger = migration_ledger_snapshot(&database.admin).await;
    assert_eq!(applied_ledger.len(), 2);
    assert_eq!(applied_ledger[0].0, None);
    assert_eq!(applied_ledger[0].1, first_manifest.package_revision);
    assert_eq!(applied_ledger[0].2, 1);
    assert_eq!(applied_ledger[0].4, "applied");
    assert_eq!(
        applied_ledger[1].0.as_deref(),
        Some(initial.package_revision.as_str())
    );
    assert_eq!(applied_ledger[1].1, active.package_revision);
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
    let second_startup = local_context(PackageIntent::Startup {
        active_revision: &active.package_revision,
        active_sequence: 2,
    });
    prepare_startup(
        second.root.path(),
        &second_startup,
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
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await;
    assert!(matches!(
        old_process,
        Err(StartupError::DatabaseUnready) | Err(StartupError::PackageRefused)
    ));
    drop(runtime);

    let wrong_schema = PackageFixture::build(
        "local",
        2,
        Some(&first_manifest.package_revision),
        fingerprint(7),
        PlanChoice::SecondTable,
        None,
    );
    let wrong_manifest = read_envelope(wrong_schema.root.path()).signed;
    let wrong_startup = local_context(PackageIntent::Startup {
        active_revision: &wrong_manifest.package_revision,
        active_sequence: 2,
    });
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
             SET active_package_revision = $1
             WHERE singleton",
            &[&wrong_manifest.package_revision],
        )
        .await
        .expect("test binds the active revision while leaving the real schema fingerprint intact");
    let mut runtime = pool.get_for_test().await.expect("runtime reconnects");
    let refused = prepare_startup(
        wrong_schema.root.path(),
        &wrong_startup,
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
             SET active_package_revision = $1
             WHERE singleton",
            &[&active.package_revision],
        )
        .await
        .expect("test restores the active revision after schema mismatch proof");

    let third = PackageFixture::build(
        "local",
        3,
        Some(&active.package_revision),
        target_schema.clone(),
        PlanChoice::ThirdTable,
        None,
    );
    let third_context = local_context(PackageIntent::Activation {
        active_revision: &active.package_revision,
        active_sequence: 2,
    });
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
        Some(MigrationError::PackageBinding),
        "a no-op startup package cannot clear failed maintenance"
    );
    assert_eq!(
        migration_ledger_snapshot(&database.admin).await,
        failed_ledger
    );

    let wrong_recovery = PackageFixture::build(
        "local",
        4,
        Some(&active.package_revision),
        third_schema.clone(),
        PlanChoice::ThirdTable,
        None,
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
            "SELECT maintenance_status, maintenance_target_revision
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await
        .expect("failed target remains readable");
    assert_eq!(failed_target.get::<_, String>(0), "failed");
    assert_eq!(
        failed_target.get::<_, String>(1),
        verified_third.manifest().package_revision
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
    assert_eq!(
        recovered.package_revision,
        verified_third.manifest().package_revision
    );
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

    let first = PackageFixture::build(
        "local",
        1,
        None,
        fingerprint(1),
        PlanChoice::WebhookSchema,
        None,
    );
    let provisional_first = load_package(
        first.root.path(),
        &local_context(PackageIntent::InitialActivation),
    )
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
    let verified_first = load_package(
        first.root.path(),
        &local_context(PackageIntent::InitialActivation),
    )
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
        "local",
        2,
        Some(&active.package_revision),
        first_fingerprint,
        PlanChoice::WebhookSecondTable,
        None,
    );
    let activation_context = local_context(PackageIntent::Activation {
        active_revision: &active.package_revision,
        active_sequence: 1,
    });
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
    assert_eq!(upgraded.package_sequence, 2);
    let after_upgrade = registry_state_snapshot(&database.admin).await;
    assert_eq!(after_upgrade.4, upgraded.package_revision);
    assert_eq!(after_upgrade.7, "ready");

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
    assert_eq!(retained.get::<_, String>(0), active.package_revision);
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
    registry: &registry_server::CompiledRegistry,
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
}

fn predecessor_plan_choice(plan: PlanChoice) -> PlanChoice {
    match plan {
        PlanChoice::Schema | PlanChoice::SecondTable => PlanChoice::Schema,
        PlanChoice::ThirdTable => PlanChoice::SecondTable,
        PlanChoice::WebhookSchema => PlanChoice::WebhookSchema,
        PlanChoice::WebhookSecondTable => PlanChoice::WebhookSchema,
    }
}

fn canonical_sequence_for_plan(plan: PlanChoice) -> u64 {
    match plan {
        PlanChoice::Schema => 1,
        PlanChoice::SecondTable => 2,
        PlanChoice::ThirdTable => 3,
        PlanChoice::WebhookSchema => 1,
        PlanChoice::WebhookSecondTable => 2,
    }
}

fn compile_fixture_registry(
    environment: &str,
    sequence: u64,
    plan: PlanChoice,
) -> registry_server::CompiledRegistry {
    let module_bytes = module_bytes(plan);
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    let project_bytes = project_bytes(environment, sequence, &module_digest(&module));
    let project = parse_project_yaml(&project_bytes).expect("fixture project parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("fixture project compiles in production")
}

struct PackageFixture {
    root: TempRoot,
    anchor: Option<PathBuf>,
}

impl PackageFixture {
    fn build(
        environment: &str,
        sequence: u64,
        prior_revision: Option<&str>,
        schema_fingerprint: String,
        plan: PlanChoice,
        signing: Option<&PrivateJwk>,
    ) -> Self {
        let root = TempRoot::create();
        let module_bytes = module_bytes(plan);
        let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
        let project_bytes = project_bytes(environment, sequence, &module_digest(&module));
        let (signature_policy, anchor) = if let Some(signing) = signing {
            let key_id = signing.public().kid.expect("generated key has kid");
            (
                SignaturePolicy {
                    threshold: 1,
                    key_ids: vec![key_id.clone()],
                },
                Some((key_id, signing.public())),
            )
        } else {
            (
                SignaturePolicy {
                    threshold: 0,
                    key_ids: Vec::new(),
                },
                None,
            )
        };

        let migration_plan = if prior_revision.is_none() {
            PackageMigrationPlanInput::InitialCompiledDdl
        } else {
            let predecessor = predecessor_plan_choice(plan);
            let prior_registry = compile_fixture_registry(
                environment,
                canonical_sequence_for_plan(predecessor),
                predecessor,
            );
            PackageMigrationPlanInput::Successor {
                prior_registry: Box::new(prior_registry),
            }
        };
        let prepared = prepare_package(build_request(BuildRequestParts {
            environment,
            sequence,
            prior_revision,
            schema_fingerprint,
            project_bytes,
            module_bytes,
            migration_plan,
            signature_policy,
        }))
        .expect("fixture package prepares");
        let signatures = signing
            .map(|key| {
                let signature =
                    sign(prepared.canonical_signed_bytes(), key).expect("test package signs");
                vec![PackageSignature {
                    key_id: key.public().kid.expect("generated key has kid"),
                    signature_hex: hex(&signature),
                }]
            })
            .unwrap_or_default();
        prepared
            .publish_to_directory(root.path(), signatures)
            .expect("fixture package publishes");

        let anchor_path = anchor.map(|(key_id, public)| {
            let path = root.path().with_extension("trust.json");
            write_json(
                &path,
                &PackageTrustAnchor {
                    api_version: TRUST_ANCHOR_API_VERSION.to_owned(),
                    environment: environment.to_owned(),
                    instance_id: INSTANCE.to_owned(),
                    database_id: DATABASE.to_owned(),
                    threshold: 1,
                    keys: vec![TrustAnchorKey {
                        key_id,
                        jwk: serde_json::to_value(public).expect("public JWK serializes"),
                    }],
                },
            );
            path
        });
        Self {
            root,
            anchor: anchor_path,
        }
    }

    fn context<'a>(&'a self, intent: PackageIntent<'a>) -> PackageLoadContext<'a> {
        PackageLoadContext {
            environment: "production",
            instance_id: INSTANCE,
            database_id: DATABASE,
            database_initialization_environment: "production",
            compiler_source_revision: SOURCE_REVISION,
            trust_anchor: self.anchor.as_deref(),
            intent,
        }
    }
}

impl Drop for PackageFixture {
    fn drop(&mut self) {
        if let Some(anchor) = &self.anchor {
            let _ = fs::remove_file(anchor);
        }
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
            "registry-server-package-{}-{nanos}-{ordinal}",
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
            .is_some_and(|name| name.starts_with("registry-server-package-"))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn project_bytes(environment: &str, sequence: u64, module_digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en"}},"package":{{"environment":"{environment}","instanceId":"{INSTANCE}","sequence":{sequence},"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"name":"Package Test Publisher"}}}},"dataset":{{"title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    )
    .into_bytes()
}

fn project_bytes_without_manifest(
    environment: &str,
    sequence: u64,
    module_digest: &str,
) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en"}},"package":{{"environment":"{environment}","instanceId":"{INSTANCE}","sequence":{sequence},"sourceRevision":"{SOURCE_REVISION}"}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    )
    .into_bytes()
}

fn module_bytes(plan: PlanChoice) -> Vec<u8> {
    let second = if matches!(
        plan,
        PlanChoice::SecondTable | PlanChoice::ThirdTable | PlanChoice::WebhookSecondTable
    ) {
        r#",{"id":"second-record","route":"second-records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"writer","principalClaim":"principal","operations":["get","create"],"readableFields":["code"],"writableFields":["code"]}]}"#
    } else {
        ""
    };
    let third = if matches!(plan, PlanChoice::ThirdTable) {
        r#",{"id":"third-record","route":"third-records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}]}"#
    } else {
        ""
    };
    let events = if matches!(
        plan,
        PlanChoice::WebhookSchema | PlanChoice::WebhookSecondTable
    ) {
        r#","events":[{"id":"neutral-created-v1","trigger":"created","projection":["code"],"webhook":{"destinationId":"neutral-events"}}]"#
    } else {
        ""
    };
    format!(
        r#"{{"id":"core","version":"1","entities":[{{"id":"neutral-record","route":"neutral-records","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":8,"classification":"internal"}}],"accessProfiles":[{{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"]}}]{events}}}{second}{third}]}}"#
    )
    .into_bytes()
}

fn derived_module_bytes() -> Vec<u8> {
    br#"{"id":"core","version":"1","entities":[{"id":"neutral-record","route":"neutral-records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":32,"classification":"internal"}],"derived":[{"id":"summary","sql":"sql/summary.sql","key":"id","fields":[{"id":"summary","type":"string","maxLength":64,"classification":"internal"}]}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code","summary"]}]}]}"#.to_vec()
}

fn derived_asset_request(sql: &[u8]) -> PackageBuildRequest {
    let module_bytes = derived_module_bytes();
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
        environment: "local",
        sequence: 1,
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes: project_bytes("local", 1, &digest),
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
    });
    request.modules[0].assets = vec![PackageSourceFile {
        path: "sql/summary.sql".to_owned(),
        bytes: sql.to_vec(),
    }];
    request
}

struct BuildRequestParts<'a> {
    environment: &'a str,
    sequence: u64,
    prior_revision: Option<&'a str>,
    schema_fingerprint: String,
    project_bytes: Vec<u8>,
    module_bytes: Vec<u8>,
    migration_plan: PackageMigrationPlanInput,
    signature_policy: SignaturePolicy,
}

fn build_request(parts: BuildRequestParts<'_>) -> PackageBuildRequest {
    PackageBuildRequest {
        environment: parts.environment.to_owned(),
        instance_id: INSTANCE.to_owned(),
        database_id: DATABASE.to_owned(),
        sequence: parts.sequence,
        prior_revision: parts.prior_revision.map(str::to_owned),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: parts.schema_fingerprint,
        signature_policy: parts.signature_policy,
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

fn local_context(intent: PackageIntent<'_>) -> PackageLoadContext<'_> {
    PackageLoadContext {
        environment: "local",
        instance_id: INSTANCE,
        database_id: DATABASE,
        database_initialization_environment: "local",
        compiler_source_revision: SOURCE_REVISION,
        trust_anchor: None,
        intent,
    }
}

async fn apply_package(
    database: &TestDatabase,
    package: &registry_server::package::VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
    lock_timeout: Duration,
    statement_timeout: Duration,
) -> registry_server::migration::Result<ExpectedRegistryIdentity> {
    let timeouts = ApplyTimeouts::new(lock_timeout, statement_timeout)
        .expect("test apply timeouts are bounded");
    apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        package,
        precondition,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        timeouts,
    ))
    .await
}

async fn apply_package_with_event_destination_compatibility(
    database: &TestDatabase,
    package: &registry_server::package::VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
    inventory: &EventDestinationCompatibilityInventory,
) -> registry_server::migration::Result<ExpectedRegistryIdentity> {
    let timeouts = ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(1))
        .expect("test apply timeouts are bounded");
    apply_verified_package(
        ApplyVerifiedPackageRequest::new(
            &database.migration_config,
            package,
            precondition,
            ApplyRoles::new(&database.migration_role, &database.runtime_role),
            timeouts,
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
                &active.package_revision,
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
                 (event_id, compiled_delivery_id, logical_destination_id,
                  destination_binding_digest, package_revision, schema_fingerprint,
                  data_schema, classification_ceiling, authentication_profile, delivery_mode,
                  attempt_timeout_ms, initial_backoff_ms, maximum_backoff_ms,
                  exponential_backoff_multiplier, maximum_attempts, retry_delays_ms,
                  maximum_payload_bytes, payload_digest, deployed_attempt_timeout_ms,
                  deployed_maximum_attempts, dead_letter, operator_replay)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'internal', 'hmac_sha256_v1',
                     'after_commit', 5000, 1000, 8000, 2, 5, $8, 1024, $9,
                     4000, 4, 'required', true)",
            &[
                &event_id,
                &compiled_delivery_id,
                &logical_destination_id,
                &binding_digest,
                &active.package_revision,
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
    trust_anchor: PathBuf,
}

impl EventDestinationCompatibilityFixture {
    fn create() -> Self {
        let root = TempRoot::create();
        fs::create_dir(root.path()).expect("destination compatibility root creates");
        let secret_root = root.path().join("secrets");
        let package_root = root.path().join("package");
        fs::create_dir(&secret_root).expect("destination compatibility secrets create");
        fs::create_dir(&package_root).expect("destination compatibility package root creates");
        let trust_anchor = root.path().join("trust-anchor.json");
        fs::write(&trust_anchor, "{}").expect("destination compatibility trust file writes");
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
            trust_anchor,
        }
    }

    fn inventory(
        &self,
        registry: &registry_server::CompiledRegistry,
        path: &str,
    ) -> EventDestinationCompatibilityInventory {
        let raw = format!(
            r#"apiVersion: registry.registrystack.org/server-runtime/v1alpha1
kind: RegistryServerRuntimeConfig
listener:
  bind: 127.0.0.1:8080
  trustedProxy: direct
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
  trustAnchorPath: {}
  compilerSourceRevision: {SOURCE_REVISION}
  activeRevision: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  activeSequence: 1
authentication:
  oidc:
    issuer: https://issuer.example
    audience: urn:registry-server:webhook-upgrade
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
            self.trust_anchor.display(),
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
    i64,
    String,
    Option<String>,
) {
    let row = client
        .query_one(
            "SELECT package_id, environment, instance_id, database_id,
                    active_package_revision, schema_fingerprint, package_sequence,
                    maintenance_status, maintenance_target_revision
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
        row.get(7),
        row.get(8),
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
            "SELECT source_package_revision, target_package_revision, package_sequence,
                    statement_checksums, outcome, started_at::text, completed_at::text
             FROM registry_internal.registry_migrations
             ORDER BY package_sequence, target_package_revision",
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

fn rewrite_unsigned(root: &Path, mutate: impl FnOnce(&mut PackageManifest)) {
    let mut envelope = read_envelope(root);
    mutate(&mut envelope.signed);
    let migration_plan_bytes = canonicalize_json(
        &serde_json::to_value(&envelope.signed.migration_plan).expect("value serializes"),
    )
    .expect("value canonicalizes");
    let migration_plan_path = root.join("database/migration-plan.json");
    if migration_plan_path.is_file() {
        fs::write(&migration_plan_path, &migration_plan_bytes).expect("migration plan file writes");
        if let Some(entry) = envelope
            .signed
            .files
            .iter_mut()
            .find(|entry| entry.path == "database/migration-plan.json")
        {
            entry.size = migration_plan_bytes.len() as u64;
            entry.sha256 = format!("sha256:{}", hex(&Sha256::digest(&migration_plan_bytes)));
        }
    }
    envelope.signed.package_revision.clear();
    envelope.signed.package_revision =
        derive_package_revision(&envelope.signed).expect("mutated revision derives");
    envelope.signatures.clear();
    write_json(&root.join("package.json"), &envelope);
}

fn rewrite_envelope(root: &Path, mutate: impl FnOnce(&mut PackageEnvelope)) {
    let mut envelope = read_envelope(root);
    mutate(&mut envelope);
    write_json(&root.join("package.json"), &envelope);
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
            .signed
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
            .signed
            .files
            .iter()
            .find(|entry| entry.role == PackageFileRole::LossyManifestProjection)
            .expect("Manifest projection entry exists")
            .path,
    )
}

fn load_error(root: &Path, context: &PackageLoadContext<'_>) -> PackageError {
    load_package(root, context)
        .err()
        .expect("package is refused")
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
