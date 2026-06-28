use std::process::Command;

#[test]
fn version_output_uses_user_facing_command_name() {
    for flag in ["--version", "-V"] {
        let output = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
            .arg(flag)
            .output()
            .unwrap_or_else(|err| panic!("registry-relay {flag} runs: {err}"));

        assert!(
            output.status.success(),
            "registry-relay {flag} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("registry-relay {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}
