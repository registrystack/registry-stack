// SPDX-License-Identifier: Apache-2.0
use std::process::Command;

#[test]
fn repeated_posture_flags_are_refused_before_loading_configuration() {
    for args in [
        &[
            "--posture",
            "production",
            "serve",
            "--posture",
            "development",
        ][..],
        &["--posture=production", "serve", "--posture=development"],
        &["--posture=production", "serve", "--posture=production"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_documents"))
            .args(["--runtime-config", "/nonexistent/runtime.yaml"])
            .args(args)
            .env_remove("REGISTRY_STACK_POSTURE")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            stderr.contains("platform.posture.conflict"),
            "{args:?}: {stderr}"
        );
    }
}
