// SPDX-License-Identifier: Apache-2.0
use std::process::Command;

#[test]
fn openapi_validates_the_environment_without_changing_its_output() {
    let run = |posture| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence-oid4vci"));
        command.arg("openapi").env_remove("REGISTRY_STACK_POSTURE");
        if let Some(posture) = posture {
            command.env("REGISTRY_STACK_POSTURE", posture);
        }
        command.output().unwrap()
    };

    let invalid = run(Some("developmnt"));
    let stderr = String::from_utf8_lossy(&invalid.stderr);
    assert_eq!(invalid.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("platform.posture.invalid-value"),
        "{stderr}"
    );
    assert!(invalid.stdout.is_empty());

    let default = run(None);
    let development = run(Some("development"));
    assert!(default.status.success(), "{default:?}");
    assert!(development.status.success(), "{development:?}");
    assert_eq!(default.stdout, development.stdout);
}
