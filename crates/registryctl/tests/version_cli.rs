use std::process::Command;

#[test]
fn version_output_uses_user_facing_command_name() {
    let output = Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .arg("--version")
        .output()
        .expect("registryctl --version runs");

    assert!(
        output.status.success(),
        "registryctl --version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("registryctl {}\n", env!("CARGO_PKG_VERSION"))
    );
}
