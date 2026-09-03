// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

const CONFIG_VALUE_CANARY: &str = "breg-doctor-config-value-canary";
const PATH_VALUE_CANARY: &str = "breg-doctor-path-value-canary";
static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> Self {
        let path = std::env::current_dir()
            .expect("current directory is available")
            .join(format!(
                "bregctl-doctor-test-{}-{}",
                std::process::id(),
                TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&path).expect("test directory is created");
        assert!(path.is_absolute());
        Self { path }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_dir_all(&self.path).expect("test directory is removed");
        }
    }
}

fn run(runtime_config: &Path) -> (u8, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(
        [
            OsStr::new("bregctl"),
            OsStr::new("--format"),
            OsStr::new("json"),
            OsStr::new("doctor"),
            OsStr::new("--runtime-config"),
            runtime_config.as_os_str(),
        ],
        &mut stdout,
        &mut stderr,
    );
    (
        if status == std::process::ExitCode::SUCCESS {
            0
        } else {
            1
        },
        String::from_utf8(stdout).expect("stdout is UTF-8"),
        String::from_utf8(stderr).expect("stderr is UTF-8"),
    )
}

#[test]
fn doctor_help_names_the_absolute_runtime_configuration_contract() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status =
        registry_bregctl::run_from(["bregctl", "doctor", "--help"], &mut stdout, &mut stderr);

    assert_eq!(status, std::process::ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let help = String::from_utf8(stdout).expect("help is UTF-8");
    assert!(help.contains("--runtime-config <ABSOLUTE_FILE>"));
    assert!(help.contains("configured startup dependencies"));
    assert!(help.contains("without binding a listener"));
    assert!(!help.contains("complete startup readiness"));
}

#[test]
fn path_disclosure_threat_is_enforced_by_refusing_a_relative_runtime_config_negative() {
    let relative = Path::new(PATH_VALUE_CANARY);
    let (status, stdout, stderr) = run(relative);

    assert_eq!(status, 1);
    assert!(stderr.is_empty());
    assert!(!stdout.contains(PATH_VALUE_CANARY));
    let report: Value = serde_json::from_str(&stdout).expect("failure is JSON");
    assert_eq!(report["command"], "doctor");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "startup.runtime_config.path_invalid"
    );
    assert_tool_diagnostic(
        &report["diagnostics"][0],
        "runtime_configuration",
        "correct_runtime_configuration",
    );
}

#[test]
fn startup_value_disclosure_and_listener_activation_threats_are_enforced_by_prepare_negative() {
    let directory = TestDirectory::create();
    let runtime_config = directory.path.join("runtime.yaml");
    let probe = TcpListener::bind("127.0.0.1:0").expect("probe listener binds");
    let address = probe.local_addr().expect("probe address is available");
    drop(probe);
    fs::write(
        &runtime_config,
        format!("listener:\n  bind: {address}\nunexpected: {CONFIG_VALUE_CANARY}\n"),
    )
    .expect("invalid runtime configuration is written");

    let (status, stdout, stderr) = run(&runtime_config);

    assert_eq!(status, 1);
    assert!(stderr.is_empty());
    assert!(!stdout.contains(CONFIG_VALUE_CANARY));
    assert!(!stdout.contains(runtime_config.to_str().expect("path is UTF-8")));
    let report: Value = serde_json::from_str(&stdout).expect("failure is JSON");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "startup.runtime_config.refused"
    );
    assert_tool_diagnostic(
        &report["diagnostics"][0],
        "runtime_configuration",
        "correct_runtime_configuration",
    );

    let listener = TcpListener::bind(address)
        .expect("startup preparation refuses without binding the configured listener");
    drop(listener);
}

fn assert_tool_diagnostic(diagnostic: &Value, artifact: &str, suggested_action: &str) {
    let keys = diagnostic
        .as_object()
        .expect("diagnostic is an object")
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        keys,
        std::collections::BTreeSet::from([
            "artifact",
            "code",
            "message",
            "path",
            "severity",
            "suggestedAction",
        ])
    );
    assert_eq!(diagnostic["artifact"], artifact);
    assert_eq!(diagnostic["suggestedAction"], suggested_action);
}
