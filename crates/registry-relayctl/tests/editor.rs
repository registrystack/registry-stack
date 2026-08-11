// SPDX-License-Identifier: Apache-2.0

use std::{fs, process::Command};

use serde_json::Value;

#[test]
fn editor_command_configures_a_relay_v2_project_and_reports_json() {
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join("registry.yaml"),
        "apiVersion: relay.registrystack.org/v2alpha1\nkind: RegistryContract\n",
    )
    .unwrap();

    for _ in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_relayctl"))
            .args(["--json", "tooling", "editor"])
            .arg(project.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert!(output.stderr.is_empty());
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["schemaVersion"], "relayctl.editor.v1");
        assert_eq!(report["status"], "configured");
        assert_eq!(report["files"].as_array().unwrap().len(), 6);
    }

    for path in [
        ".relay-v2-editor/schemas/registry.schema.json",
        ".relay-v2-editor/schemas/runtime.schema.json",
        ".relay-v2-editor/manifest.json",
        ".vscode/extensions.json",
        ".vscode/settings.json",
        ".zed/settings.json",
    ] {
        assert!(project.path().join(path).is_file(), "{path}");
    }
}
