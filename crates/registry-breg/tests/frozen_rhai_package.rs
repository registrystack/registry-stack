// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

//! Frozen package compatibility across compiler generations.
//!
//! `tests/fixtures/person-registration-rhai-package` is a complete package
//! produced by the current package compiler. The current fixture pins exact
//! bytes, current integrity inspection, and Rhai execution.
//! `person-registration-rhai-package-pre-statistics` preserves the package
//! produced before engine-owned statistical release storage changed every
//! package DDL. It pins the compatibility contract used for successor planning:
//! historical bytes remain a readable predecessor without being rederived as a
//! current candidate package. It carries the retired package apiVersion, so it
//! also pins that a retired package is read only as a predecessor.
//!
//! The loading tests read a temporary copy, so a run never touches the frozen
//! bytes.
//!
//! To deliberately re-freeze the fixture after an approved package-format
//! change, delete the directory and run the ignored writer test:
//!
//! ```text
//! cargo test --locked -p registry-breg --test frozen_rhai_package -- --ignored write_frozen_fixture
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use registry_breg::action_handler::{evaluate_action_detailed, ActionHandlerOutcome};
use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_yaml, ModuleAssetSource};
use registry_breg::migration::{successor_plan_is_empty, successor_plan_is_empty_for_predecessor};
use registry_breg::package::{
    change_set_to_applicable_migration_plan, compiled_registry_change_set_from_baseline,
    inspect_package_integrity, load_package, load_predecessor_package,
    prepare_package_with_project_assets, PackageBuildRequest, PackageEnvelope, PackageError,
    PackageLoadContext, PackageMigrationPlanInput, PackageSourceFile, VerifiedPredecessorPackage,
    PACKAGE_API_VERSION, PACKAGE_KIND, RETIRED_PACKAGE_API_VERSION,
};
use registry_breg::CompiledRegistry;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::package::{write_sum_file, PackageLimits, SUM_FILE};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const ENVIRONMENT: &str = "local";
const SOURCE_REVISION: &str = "person-registration-rhai-acceptance-0.1.0";
const HANDLER_SCRIPTS: [&str; 2] = [
    "scripts/register-person.rhai",
    "scripts/register-person-with-registration.rhai",
];

fn acceptance_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/person-registration-rhai")
}

fn frozen_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/person-registration-rhai-package")
}

fn legacy_frozen_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/person-registration-rhai-package-pre-statistics")
}

/// A temporary copy of the frozen package, leaving the frozen bytes untouched.
fn frozen_copy() -> tempfile::TempDir {
    fixture_copy(&frozen_root())
}

fn legacy_frozen_copy() -> tempfile::TempDir {
    fixture_copy(&legacy_frozen_root())
}

fn fixture_copy(root: &Path) -> tempfile::TempDir {
    let copy = tempfile::Builder::new()
        .prefix("registry-frozen-package-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("temporary package directory");
    copy_tree(root, copy.path());
    copy
}

fn copy_tree(source: &Path, destination: &Path) {
    for entry in fs::read_dir(source).expect("frozen package directory reads") {
        let entry = entry.expect("frozen package entry reads");
        let target = destination.join(entry.file_name());
        if entry
            .file_type()
            .expect("frozen package entry type")
            .is_dir()
        {
            fs::create_dir(&target).expect("package copy directory creates");
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("package file copies");
        }
    }
}

/// The acceptance project with the source revision the frozen package carries.
fn local_project() -> registry_breg::contract::RegistryProject {
    let mut project = parse_project_yaml(
        &fs::read(acceptance_root().join("registry.yaml"))
            .expect("the person-registration-rhai acceptance project is present"),
    )
    .expect("the person-registration-rhai acceptance project parses");
    let identity = project
        .package
        .as_mut()
        .expect("the acceptance project declares a package identity");
    identity.source_revision = SOURCE_REVISION.to_owned();
    project
}

/// The package's `source/registry.yaml`: the acceptance project as JSON, which
/// the reader accepts as YAML. The serialized source writes an absent optional
/// member as null, which an authored file never carries, so nulls are removed.
fn local_project_bytes() -> Vec<u8> {
    fn remove_nulls(value: &mut Value) {
        match value {
            Value::Object(members) => {
                members.retain(|_, member| !member.is_null());
                members.values_mut().for_each(remove_nulls);
            }
            Value::Array(items) => items.iter_mut().for_each(remove_nulls),
            _ => {}
        }
    }
    let mut value = serde_json::to_value(local_project()).unwrap();
    remove_nulls(&mut value);
    serde_json::to_vec(&value).unwrap()
}

fn handler_assets() -> Vec<PackageSourceFile> {
    HANDLER_SCRIPTS
        .into_iter()
        .map(|path| PackageSourceFile {
            path: path.to_owned(),
            bytes: fs::read(acceptance_root().join(path))
                .unwrap_or_else(|error| panic!("the handler script {path} is present: {error}")),
        })
        .collect()
}

fn module_assets(assets: &[PackageSourceFile]) -> Vec<ModuleAssetSource> {
    assets
        .iter()
        .map(|asset| ModuleAssetSource {
            module: None,
            path: asset.path.clone(),
            bytes: asset.bytes.clone(),
        })
        .collect()
}

fn fixture_journeys() -> PackageSourceFile {
    PackageSourceFile {
        path: "tests/journeys.yaml".to_owned(),
        bytes: fs::read(acceptance_root().join("tests/journeys.yaml"))
            .expect("the acceptance journeys are present"),
    }
}

/// Build the exact package the frozen fixture captured, from the same governed
/// source, with a schema fingerprint derived from the governed DDL so the
/// request is a deterministic function of the project alone.
fn prepare_frozen_package() -> registry_breg::package::PreparedPackage {
    let assets = handler_assets();
    let compiled = compile_project_with_assets(
        &local_project(),
        &[],
        &module_assets(&assets),
        CompileProfile::Production,
    )
    .expect("the person-registration-rhai acceptance project compiles");
    let request = PackageBuildRequest {
        from_package_digest: None,
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: digest(compiled.ddl().script().as_bytes()),
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: local_project_bytes(),
        },
        modules: vec![],
        fixture_journeys: fixture_journeys(),
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    };
    prepare_package_with_project_assets(request, assets)
        .expect("the frozen package builds from the acceptance project")
}

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

fn collect_files(root: &Path, directory: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
    for entry in fs::read_dir(directory).expect("the fixture directory is readable") {
        let entry = entry.expect("the fixture directory entry is readable");
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, files);
        } else {
            let relative = path
                .strip_prefix(root)
                .expect("the fixture path is inside the fixture root")
                .to_string_lossy()
                .to_string();
            files.insert(
                relative,
                fs::read(&path).expect("the fixture file is readable"),
            );
        }
    }
}

fn register_person(registry: &CompiledRegistry) -> registry_breg::model::CompiledAction {
    registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-person")
        .expect("the frozen package carries the register-person action")
        .clone()
}

fn handler_inputs(identifier: &str, given: &str, family: &str) -> Map<String, Value> {
    Map::from_iter([
        (
            "identifier".to_owned(),
            Value::String(identifier.to_owned()),
        ),
        ("given-name".to_owned(), Value::String(given.to_owned())),
        ("family-name".to_owned(), Value::String(family.to_owned())),
    ])
}

#[test]
fn frozen_package_bytes_match_the_current_compiler() {
    let package = prepare_frozen_package();
    let root = frozen_root();
    let mut committed = BTreeMap::new();
    collect_files(&root, &root, &mut committed);
    assert!(
        !committed.is_empty(),
        "the frozen fixture directory {} is committed",
        root.display()
    );

    let envelope = package.envelope();
    let manifest_bytes = canonicalize_json(&serde_json::to_value(&envelope).unwrap())
        .expect("the envelope renders as canonical JSON");
    assert_eq!(
        committed.remove("package.json").as_deref(),
        Some(manifest_bytes.as_slice()),
        "the frozen package manifest must match the current compiler byte-for-byte"
    );

    assert_eq!(
        committed.remove(SUM_FILE).map(|sums| digest(&sums)),
        Some(
            package
                .package_digest()
                .expect("the frozen package digest derives")
        ),
        "the frozen package digest must match the current compiler"
    );

    let rebuilt = package.file_bytes().clone();
    assert_eq!(
        committed.keys().collect::<Vec<_>>(),
        rebuilt.keys().collect::<Vec<_>>(),
        "the frozen package file set must match the current compiler exactly"
    );
    for (path, bytes) in &rebuilt {
        assert_eq!(
            committed.get(path).map(Vec::as_slice),
            Some(bytes.as_slice()),
            "the frozen package file {path} must match the current compiler byte-for-byte"
        );
    }
}

#[test]
fn package_manifest_refuses_unknown_engine_features() {
    let package = prepare_frozen_package();
    let mut envelope = serde_json::to_value(package.envelope()).unwrap();
    envelope["manifest"]["engineFeatures"] = json!(["unknown_engine_feature"]);
    assert!(serde_json::from_value::<PackageEnvelope>(envelope).is_err());
}

#[test]
fn current_package_without_required_engine_feature_is_predecessor_only() {
    let package = frozen_copy();
    let manifest_path = package.path().join("package.json");
    let mut envelope: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    envelope["manifest"]
        .as_object_mut()
        .unwrap()
        .remove("engineFeatures");
    fs::write(
        &manifest_path,
        canonicalize_json(&envelope).expect("mutated envelope canonicalizes"),
    )
    .unwrap();
    fs::remove_file(package.path().join(SUM_FILE)).unwrap();
    write_sum_file(
        package.path(),
        None,
        &PackageLimits {
            max_files: 1_026,
            max_file_bytes: 16 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_depth: 16,
            max_path_bytes: 512,
        },
        "test package",
    )
    .expect("mutated package envelope is closed");

    let context = PackageLoadContext {
        database_initialization_environment: ENVIRONMENT,
    };
    assert!(matches!(
        load_package(package.path(), &context),
        Err(PackageError::Derivation)
    ));
    assert!(load_predecessor_package(package.path(), &context).is_ok());
}

#[test]
fn frozen_package_loads_and_runs_its_rhai_handler() {
    let package = frozen_copy();
    let inspected =
        inspect_package_integrity(package.path()).expect("the frozen package still verifies");
    let action = register_person(inspected.registry());
    let handler = action
        .handler
        .as_ref()
        .expect("the action declares a handler");
    assert_eq!(
        handler.kind,
        registry_breg::model::CompiledActionHandlerKind::Rhai
    );
    assert_eq!(handler.abi, registry_breg::contract::ACTION_HANDLER_ABI_V1);
    assert_eq!(handler.script_path, "scripts/register-person.rhai");

    let accepted = evaluate_action_detailed(
        &action,
        &handler_inputs("0123456789012", "  Mina  ", " Example "),
        Instant::now() + Duration::from_secs(30),
    )
    .expect("the frozen handler still evaluates");
    match accepted {
        ActionHandlerOutcome::Effects(effects) => {
            assert_eq!(effects.len(), 1);
            assert_eq!(effects[0].id, "person");
        }
        ActionHandlerOutcome::Refusal(refusal) => {
            panic!("the frozen handler must accept a full name, refused with {refusal:?}");
        }
    }

    let refused = evaluate_action_detailed(
        &action,
        &handler_inputs("0123456789012", "   ", "  "),
        Instant::now() + Duration::from_secs(30),
    )
    .expect("a declared refusal is a successful handler outcome");
    match refused {
        ActionHandlerOutcome::Refusal(refusal) => {
            assert_eq!(refusal.code, "blank-name");
            assert_eq!(refusal.field.as_deref(), Some("given-name"));
        }
        ActionHandlerOutcome::Effects(effects) => {
            panic!("the blank-name input must refuse, produced {effects:?}");
        }
    }
}

#[test]
fn frozen_package_remains_a_readable_predecessor() {
    let package = legacy_frozen_copy();
    let context = PackageLoadContext {
        database_initialization_environment: ENVIRONMENT,
    };
    let predecessor = load_predecessor_package(package.path(), &context)
        .expect("the frozen package remains a verified predecessor baseline");
    let baseline = predecessor.migration_baseline();
    assert_eq!(baseline.package_digest, predecessor.package_digest());
    assert_eq!(baseline.registry_id, "person-registration-rhai");
    assert!(
        baseline
            .actions
            .actions
            .iter()
            .any(|action| action.id == "register-person"),
        "the predecessor baseline carries the compiled action inventory"
    );
    assert!(!predecessor.statistical_release_store_present());

    let candidate = prepare_frozen_package();
    let changes = compiled_registry_change_set_from_baseline(
        baseline,
        candidate.registry(),
        predecessor.package_digest(),
    );
    let plan = change_set_to_applicable_migration_plan(&changes)
        .expect("the current compiler plans an automatic successor from the legacy baseline");
    assert_eq!(
        plan.from_package_digest.as_deref(),
        Some(predecessor.package_digest())
    );

    let assets = handler_assets();
    let successor = prepare_package_with_project_assets(
        PackageBuildRequest {
            from_package_digest: Some(predecessor.package_digest().to_owned()),
            compiler_source_revision: SOURCE_REVISION.to_owned(),
            schema_fingerprint: digest(candidate.registry().ddl().script().as_bytes()),
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes: local_project_bytes(),
            },
            modules: vec![],
            fixture_journeys: fixture_journeys(),
            migration_plan: PackageMigrationPlanInput::SuccessorFromBaseline {
                prior_baseline: Box::new(baseline.clone()),
            },
        },
        assets,
    )
    .expect("the current compiler builds a successor from the legacy package baseline");
    assert_eq!(successor.manifest().migration_plan, plan);

    let current_package = frozen_copy();
    let current_predecessor = load_predecessor_package(current_package.path(), &context)
        .expect("the current frozen package is also a verified predecessor");
    assert!(current_predecessor.statistical_release_store_present());
}

/// Rewrite a package copy's manifest into the envelope an earlier release
/// wrote, the retired apiVersion and no kind, and reseal its sum file.
fn retire_envelope(package: &Path) {
    let manifest_path = package.join("package.json");
    let mut envelope: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    assert_eq!(envelope["apiVersion"], PACKAGE_API_VERSION);
    assert_eq!(envelope["kind"], PACKAGE_KIND);
    envelope["apiVersion"] = json!(RETIRED_PACKAGE_API_VERSION);
    envelope.as_object_mut().unwrap().remove("kind");
    fs::write(
        &manifest_path,
        canonicalize_json(&envelope).expect("retired envelope canonicalizes"),
    )
    .unwrap();
    reseal(package);
}

fn reseal(package: &Path) {
    fs::remove_file(package.join(SUM_FILE)).unwrap();
    write_sum_file(
        package,
        None,
        &PackageLimits {
            max_files: 1_026,
            max_file_bytes: 16 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_depth: 16,
            max_path_bytes: 512,
        },
        "test package",
    )
    .expect("rewritten package envelope is closed");
}

/// Build the frozen project as a successor of `predecessor` and load it the
/// way `bregctl apply` loads its target.
fn verified_successor(
    predecessor: &VerifiedPredecessorPackage,
) -> (tempfile::TempDir, registry_breg::package::VerifiedPackage) {
    let candidate = prepare_frozen_package();
    let successor = prepare_package_with_project_assets(
        PackageBuildRequest {
            from_package_digest: Some(predecessor.package_digest().to_owned()),
            compiler_source_revision: SOURCE_REVISION.to_owned(),
            schema_fingerprint: digest(candidate.registry().ddl().script().as_bytes()),
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes: local_project_bytes(),
            },
            modules: vec![],
            fixture_journeys: fixture_journeys(),
            migration_plan: PackageMigrationPlanInput::SuccessorFromBaseline {
                prior_baseline: Box::new(predecessor.migration_baseline().clone()),
            },
        },
        handler_assets(),
    )
    .expect("the current compiler builds a successor from the predecessor baseline");
    let directory = tempfile::Builder::new()
        .prefix("registry-successor-package-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("temporary successor directory");
    let root = directory.path().join("package");
    successor
        .publish_to_directory(&root)
        .expect("the successor publishes");
    let context = PackageLoadContext {
        database_initialization_environment: ENVIRONMENT,
    };
    let verified = load_package(&root, &context).expect("the successor verifies");
    (directory, verified)
}

#[test]
fn a_retired_package_is_read_only_as_a_predecessor() {
    // CFG-CHANGE-2: the pre-statistics fixture is a package an earlier
    // release built, carrying the retired apiVersion and no kind. Starting,
    // inspecting, or checking it is refused as retired; reading it as the
    // deployed predecessor of a rebuild is not, so an upgrade can replace it.
    let package = legacy_frozen_copy();
    let context = PackageLoadContext {
        database_initialization_environment: ENVIRONMENT,
    };
    assert!(matches!(
        load_package(package.path(), &context),
        Err(PackageError::RetiredApiVersion)
    ));
    assert!(matches!(
        inspect_package_integrity(package.path()),
        Err(PackageError::RetiredApiVersion)
    ));
    let predecessor = load_predecessor_package(package.path(), &context)
        .expect("a retired package is still a verified predecessor");
    assert!(predecessor.carries_retired_api_version());

    let current = frozen_copy();
    let current_predecessor = load_predecessor_package(current.path(), &context)
        .expect("the current frozen package is a verified predecessor");
    assert!(!current_predecessor.carries_retired_api_version());
}

#[test]
fn a_package_names_its_kind_and_refuses_another() {
    let package = frozen_copy();
    let manifest_path = package.path().join("package.json");
    let mut envelope: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    envelope["kind"] = json!("RegistryPackage");
    fs::write(
        &manifest_path,
        canonicalize_json(&envelope).expect("mutated envelope canonicalizes"),
    )
    .unwrap();
    reseal(package.path());
    let context = PackageLoadContext {
        database_initialization_environment: ENVIRONMENT,
    };
    assert!(matches!(
        load_package(package.path(), &context),
        Err(PackageError::Integrity)
    ));
}

#[test]
fn rebuilding_a_retired_predecessor_has_apply_work_with_an_unchanged_model() {
    // The same package under the retired envelope: same model, same engine
    // capabilities. Its unchanged rebuild has an empty plan, yet it is the
    // only way off a package the runtime no longer starts, so apply must not
    // refuse it as empty. Over a current predecessor the same rebuild is
    // still an ordinary empty successor.
    let context = PackageLoadContext {
        database_initialization_environment: ENVIRONMENT,
    };
    let retired = frozen_copy();
    retire_envelope(retired.path());
    let retired_predecessor = load_predecessor_package(retired.path(), &context)
        .expect("the retired package is a verified predecessor");
    assert!(retired_predecessor.carries_retired_api_version());
    let (_directory, successor) = verified_successor(&retired_predecessor);
    assert!(successor_plan_is_empty(&successor));
    assert!(!successor_plan_is_empty_for_predecessor(
        &successor,
        &retired_predecessor
    ));

    let current = frozen_copy();
    let current_predecessor = load_predecessor_package(current.path(), &context)
        .expect("the current frozen package is a verified predecessor");
    let (_directory, successor) = verified_successor(&current_predecessor);
    assert!(successor_plan_is_empty_for_predecessor(
        &successor,
        &current_predecessor
    ));
}

#[test]
#[ignore = "re-freezes the committed fixture; run only after an approved package-format change"]
fn write_frozen_fixture() {
    let destination = frozen_root();
    assert!(
        !destination.exists(),
        "remove the existing fixture first; the writer never overwrites a frozen package"
    );
    prepare_frozen_package()
        .publish_to_directory(&destination)
        .expect("the frozen fixture is written");
    inspect_package_integrity(&destination).expect("the written fixture verifies");
}
