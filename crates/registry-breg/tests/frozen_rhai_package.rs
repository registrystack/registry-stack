// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

//! Frozen pre-change package compatibility.
//!
//! `tests/fixtures/person-registration-rhai-package` is a complete package
//! produced by the package compiler as it stood before the compiled action
//! handler representation evolved further. The directory is frozen test input:
//! it is never regenerated in place, and the tests below prove the current
//! compiler still produces every byte of it, still verifies it through
//! candidate-package inspection, still accepts it for predecessor inspection,
//! and still runs its Rhai action handler.
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
use registry_breg::package::{
    inspect_package_integrity, load_predecessor_package, prepare_package_with_project_assets,
    PackageBuildRequest, PackageMigrationPlanInput, PackageSourceFile, PredecessorPackageContext,
    SignaturePolicy,
};
use registry_breg::CompiledRegistry;
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const ENVIRONMENT: &str = "local";
const INSTANCE_ID: &str = "person-registration-rhai-acceptance";
const DATABASE_ID: &str = "person-registration-rhai";
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

/// The acceptance project bound to the unsigned local deployment identity the
/// frozen package carries.
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
    identity.environment = ENVIRONMENT.to_owned();
    identity.instance_id = INSTANCE_ID.to_owned();
    identity.sequence = 1;
    identity.source_revision = SOURCE_REVISION.to_owned();
    project
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
        environment: ENVIRONMENT.to_owned(),
        instance_id: INSTANCE_ID.to_owned(),
        database_id: DATABASE_ID.to_owned(),
        sequence: 1,
        prior_revision: None,
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: digest(compiled.ddl().script().as_bytes()),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: vec![],
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: serde_json::to_vec(&local_project()).unwrap(),
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

    let envelope = package
        .envelope(vec![])
        .expect("the unsigned envelope is valid");
    let manifest_bytes = canonicalize_json(&serde_json::to_value(&envelope).unwrap())
        .expect("the envelope renders as canonical JSON");
    assert_eq!(
        committed.remove("package.json").as_deref(),
        Some(manifest_bytes.as_slice()),
        "the frozen package manifest must match the current compiler byte-for-byte"
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
fn frozen_package_loads_and_runs_its_rhai_handler() {
    let inspected =
        inspect_package_integrity(&frozen_root()).expect("the frozen package still verifies");
    let action = register_person(inspected.registry());
    let handler = action
        .handler
        .as_ref()
        .expect("the action declares a handler");
    assert_eq!(
        handler.kind,
        registry_breg::model::CompiledChangeRequestPlannerKind::Rhai
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
    let inspected = inspect_package_integrity(&frozen_root())
        .expect("the frozen package revision is derived before predecessor binding");
    let package_revision = inspected.package_revision().to_owned();
    let context = PredecessorPackageContext {
        environment: ENVIRONMENT,
        instance_id: INSTANCE_ID,
        database_id: DATABASE_ID,
        database_initialization_environment: ENVIRONMENT,
        trust_anchor: None,
        expected_package_revision: &package_revision,
        expected_sequence: 1,
    };
    let predecessor = load_predecessor_package(&frozen_root(), &context)
        .expect("the frozen package is still accepted for predecessor inspection");
    let baseline = predecessor.migration_baseline();
    assert_eq!(baseline.package_revision, package_revision);
    assert_eq!(baseline.registry_id, "person-registration-rhai");
    assert!(
        baseline
            .actions
            .actions
            .iter()
            .any(|action| action.id == "register-person"),
        "the predecessor baseline carries the compiled action inventory"
    );
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
        .publish_to_directory(&destination, vec![])
        .expect("the frozen fixture is written");
    inspect_package_integrity(&destination).expect("the written fixture verifies");
}
