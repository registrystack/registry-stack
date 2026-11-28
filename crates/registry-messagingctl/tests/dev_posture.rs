// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn dev_help_states_the_default_and_refuses_production() {
    let output = Command::new(env!("CARGO_BIN_EXE_messagingctl"))
        .env_remove("REGISTRY_STACK_POSTURE")
        .args(["dev", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(
        help.contains("Unset means development; production is refused."),
        "{help}"
    );
}

#[test]
fn dev_refuses_explicit_production_before_writing() {
    let project = tempfile::tempdir().unwrap();
    for via_flag in [true, false] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_messagingctl"));
        command
            .env_remove("REGISTRY_STACK_POSTURE")
            .args(["--format", "json", "dev"]);
        if via_flag {
            command.args(["--posture", "production"]);
        } else {
            command.env("REGISTRY_STACK_POSTURE", "production");
        }
        let output = command.arg(project.path()).output().unwrap();
        assert_eq!(std::fs::read_dir(project.path()).unwrap().count(), 0);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let finding = &report["diagnostics"][0];
        assert_eq!(finding["code"], "platform.posture.conflict", "{report}");
        assert_eq!(
            finding["message"],
            "messagingctl dev runs under the development posture, but production was declared",
            "{report}"
        );
        assert_eq!(finding["suggestedAction"], "Drop the production declaration, or run the runtime in production with messagingctl serve.", "{report}");
    }
}
