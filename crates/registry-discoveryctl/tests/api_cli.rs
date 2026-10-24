use std::process::Command;

#[test]
fn api_and_saved_connections_are_available_without_a_runtime_config() {
    for arguments in [["api", "--help"], ["connection", "--help"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_discoveryctl"))
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
