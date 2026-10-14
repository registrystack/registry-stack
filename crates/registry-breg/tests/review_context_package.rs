// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

use std::{fs, path::Path};

use registry_breg::{
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_yaml, ModuleAssetSource},
    package::{
        inspect_package_integrity, prepare_package_with_project_assets, PackageBuildRequest,
        PackageError, PackageFileRole, PackageMigrationPlanInput, PackageSourceFile,
    },
};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::package::{write_sum_file, PackageLimits, SUM_FILE};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const INDEX: &str = "generated/review-context-schemas/index.json";
const SCHEMA: &str = "generated/review-context-schemas/correct-address.schema.json";

fn digest(bytes: &[u8]) -> String {
    let mut output = String::from("sha256:");
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

fn prepare() -> registry_breg::package::PreparedPackage {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/refactor/facility");
    let authored = fs::read_to_string(root.join("registry.yaml")).unwrap();
    let project_bytes = authored
        .replacen(
            "\ndatasets:\n",
            "\npackage:\n  sourceRevision: review-context-package-proof-1\n\ndatasets:\n",
            1,
        )
        .into_bytes();
    let project = parse_project_yaml(&project_bytes).unwrap();
    let asset = PackageSourceFile {
        path: "plans/correct-address.rhai".into(),
        bytes: fs::read(root.join("plans/correct-address.rhai")).unwrap(),
    };
    let compiled = compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: asset.path.clone(),
            bytes: asset.bytes.clone(),
        }],
        CompileProfile::Production,
    )
    .unwrap();
    prepare_package_with_project_assets(
        PackageBuildRequest {
            from_package_digest: None,
            compiler_source_revision: "review-context-package-proof-1".into(),
            schema_fingerprint: digest(compiled.ddl().script().as_bytes()),
            project: PackageSourceFile {
                path: "source/registry.yaml".into(),
                bytes: project_bytes,
            },
            modules: vec![],
            fixture_journeys: PackageSourceFile {
                path: "tests/journeys.yaml".into(),
                bytes: b"apiVersion: id.registrystack.org/formats/breg/journeys/v1\nkind: BRegJourneys\njourneys: []\n".to_vec(),
            },
            migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        },
        vec![asset],
    )
    .unwrap()
}

fn reseal(root: &Path) {
    fs::remove_file(root.join(SUM_FILE)).unwrap();
    write_sum_file(
        root,
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
    .unwrap();
}

#[test]
fn sealed_review_context_export_is_exact_and_cannot_be_omitted_or_rebound() {
    let prepared = prepare();
    let temporary = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let original = temporary.path().join("original");
    prepared.publish_to_directory(&original).unwrap();
    inspect_package_integrity(&original).unwrap();

    let envelope: Value =
        serde_json::from_slice(&fs::read(original.join("package.json")).unwrap()).unwrap();
    let files = envelope["manifest"]["files"].as_array().unwrap();
    assert!(files.iter().any(|entry| entry["path"] == INDEX
        && entry["role"] == json!(PackageFileRole::ReviewContextSchemaIndex)));
    assert!(files.iter().any(|entry| entry["path"] == SCHEMA
        && entry["role"] == json!(PackageFileRole::ReviewContextJsonSchema)));
    let index: Value = serde_json::from_slice(&fs::read(original.join(INDEX)).unwrap()).unwrap();
    assert_eq!(index["correct-address"]["path"], SCHEMA);
    assert_eq!(
        index["correct-address"]["digest"],
        digest(&fs::read(original.join(SCHEMA)).unwrap())
    );

    let missing = temporary.path().join("missing");
    prepared.publish_to_directory(&missing).unwrap();
    let mut envelope: Value =
        serde_json::from_slice(&fs::read(missing.join("package.json")).unwrap()).unwrap();
    envelope["manifest"]["files"]
        .as_array_mut()
        .unwrap()
        .retain(|entry| entry["path"] != INDEX);
    fs::remove_file(missing.join(INDEX)).unwrap();
    fs::write(
        missing.join("package.json"),
        canonicalize_json(&envelope).unwrap(),
    )
    .unwrap();
    reseal(&missing);
    assert_eq!(
        inspect_package_integrity(&missing).err(),
        Some(PackageError::Derivation)
    );

    let rebound = temporary.path().join("rebound");
    prepared.publish_to_directory(&rebound).unwrap();
    let changed = b"{\"type\":\"object\"}";
    fs::write(rebound.join(SCHEMA), changed).unwrap();
    let mut envelope: Value =
        serde_json::from_slice(&fs::read(rebound.join("package.json")).unwrap()).unwrap();
    let entry = envelope["manifest"]["files"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| entry["path"] == SCHEMA)
        .unwrap();
    entry["size"] = json!(changed.len());
    entry["sha256"] = json!(digest(changed));
    fs::write(
        rebound.join("package.json"),
        canonicalize_json(&envelope).unwrap(),
    )
    .unwrap();
    reseal(&rebound);
    assert_eq!(
        inspect_package_integrity(&rebound).err(),
        Some(PackageError::Derivation)
    );
}
