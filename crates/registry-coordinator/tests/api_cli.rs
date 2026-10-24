use std::process::Command;

#[test]
fn api_and_saved_connections_are_available_without_a_runtime_config() {
    for arguments in [["api", "--help"], ["connection", "--help"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains(if arguments[0] == "api" {
            "--connection"
        } else {
            "add"
        }));
    }
}

#[test]
fn raw_api_refuses_report_format_before_network_access() {
    let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(["api", "/v1/runs", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--format does not apply"));
}
