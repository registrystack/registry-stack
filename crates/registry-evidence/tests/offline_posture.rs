// SPDX-License-Identifier: Apache-2.0
use std::process::Command;

#[test]
fn production_only_commands_validate_the_environment() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    let missing = missing.to_str().unwrap();
    for args in [
        &["check-policy", "--verification-policy", missing][..],
        &["render-discovery-description", "--config", missing],
        &[
            "verify", "--jws", missing, "--jwks", missing, "--policy", missing,
        ],
        &[
            "verify-presentation",
            "--sd-jwt-vc-presentation",
            missing,
            "--jwks",
            missing,
            "--policy",
            missing,
        ],
    ] {
        let run = |posture| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_evidence"));
            command.args(args).env_remove("REGISTRY_STACK_POSTURE");
            if let Some(posture) = posture {
                command.env("REGISTRY_STACK_POSTURE", posture);
            }
            command.output().unwrap()
        };
        let invalid = run(Some("developmnt"));
        let stderr = String::from_utf8_lossy(&invalid.stderr);
        assert_eq!(invalid.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            stderr.contains("platform.posture.invalid-value"),
            "{args:?}: {stderr}"
        );

        let default = run(None);
        let development = run(Some("development"));
        assert_eq!(default.status, development.status, "{args:?}");
        assert_eq!(default.stdout, development.stdout, "{args:?}");
        assert_eq!(default.stderr, development.stderr, "{args:?}");
    }
}
