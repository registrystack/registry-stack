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
    // The document is structurally invalid (an unrecognized field with the
    // required members absent), so doctor names that specific configuration
    // cause instead of a generic runtime-configuration refusal.
    assert_eq!(
        report["diagnostics"][0]["code"],
        "startup.runtime_config.document"
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

#[test]
fn doctor_names_the_specific_configuration_cause_instead_of_a_generic_refusal() {
    let directory = TestDirectory::create();
    let runtime_config = directory.path.join("runtime.yaml");
    fs::write(&runtime_config, "not: [valid\n").expect("unparseable document is written");

    let (status, stdout, stderr) = run(&runtime_config);

    assert_eq!(status, 1);
    assert!(stderr.is_empty());
    let report: Value = serde_json::from_str(&stdout).expect("failure is JSON");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "startup.runtime_config.document"
    );
    assert_eq!(report["diagnostics"][0]["path"], "/");
    assert_tool_diagnostic(
        &report["diagnostics"][0],
        "runtime_configuration",
        "correct_runtime_configuration",
    );
}

#[test]
fn doctor_names_a_missing_package_root_distinctly_from_other_configuration_causes() {
    let directory = TestDirectory::create();
    let runtime_config = directory.path.join("runtime.yaml");
    let secrets_root = directory.path.join("secrets");
    fs::create_dir(&secrets_root).expect("secret provider root is created");
    fs::write(
        &runtime_config,
        format!(
            "apiVersion: registry.registrystack.org/breg-runtime/v1alpha1\n\
kind: BRegRuntimeConfig\n\
listener:\n  bind: 127.0.0.1:0\n\
identity:\n  environment: development\n  instanceId: generic-registry-1\n  databaseId: generic-registry-db-1\n  databaseInitializationEnvironment: development\n\
secretProviders:\n  file:\n    root: {secrets}\n\
database:\n  runtimeUrlRef: secret:file/runtime-database-url\n  migrationUrlRef: secret:file/migration-database-url\n  pool:\n    maxSize: 8\n  roles:\n    migration: registry_migration\n    runtime: registry_runtime\n\
package:\n  root: {missing}\n  trustAnchorPath: {missing}/trust-anchor.json\n  compilerSourceRevision: generic-registry-0.1.0\n  activeRevision: sha256:0000000000000000000000000000000000000000000000000000000000000\n  activeSequence: 1\n\
authentication:\n  oidc:\n    issuer: https://issuer.example.invalid\n    audience: generic-registry\n    allowedAlgorithm: ES256\n    accessTokenType: at+jwt\n    scopeClaim: scope\n    scopeSeparator: \" \"\n    allowedClients: [generic-registry-client]\n    deniedKids: []\n    maxTokenLifetimeSeconds: 300\n    leewayMilliseconds: 30000\n    jwksSource:\n      kind: discovery\n  authorityClaims:\n    principal: registry_principal\n    purpose: registry_purpose\n\
audit:\n  hashKeyRef: secret:file/audit-key\n\
cursor:\n  secretRef: secret:file/cursor-key\n\
eventDestinations: {{}}\n",
            secrets = secrets_root.display(),
            missing = directory.path.join("does-not-exist").display(),
        ),
    )
    .expect("runtime configuration with a missing package root is written");

    let (status, stdout, stderr) = run(&runtime_config);

    assert_eq!(status, 1);
    assert!(stderr.is_empty());
    let report: Value = serde_json::from_str(&stdout).expect("failure is JSON");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "startup.runtime_config.package_root_unavailable"
    );
    assert_eq!(report["diagnostics"][0]["path"], "/package/root");
    assert_tool_diagnostic(
        &report["diagnostics"][0],
        "runtime_configuration",
        "correct_runtime_configuration",
    );
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
