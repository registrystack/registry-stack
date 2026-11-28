// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::Path, process::Command};

#[test]
fn generate_sdk_emits_the_native_node_package_import() {
    let workspace = tempfile::tempdir().unwrap();
    let output_dir = workspace.path().join("sdk");
    let project =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/examples/minimal");
    let result = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["generate", "sdk"])
        .arg(project)
        .arg("--output")
        .arg(&output_dir)
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");

    let typescript = fs::read_to_string(output_dir.join("generated/sdk/project.ts")).unwrap();
    assert!(typescript.contains("import type { breg } from '@registrystack/client-node';"));
}
