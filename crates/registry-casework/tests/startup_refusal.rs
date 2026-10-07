//! A `casework` that refuses its packaged project at startup prints the
//! reader's CFG-DIAG-2 lines to stderr unchanged, after one sentence of its
//! own, before it opens a database.

use std::path::Path;
use std::process::Command;

use registry_casework::{
    package_limits, PACKAGE_COMMAND, POLICY_FILE, RUNTIME_CONFIG_API_VERSION, RUNTIME_CONFIG_KIND,
};

const PROJECT: &str =
    include_str!("../../../products/casework/examples/standalone-decision/casework.yaml");

fn write_runtime(root: &Path, package: &Path) -> std::path::PathBuf {
    let runtime = root.join("runtime.yaml");
    std::fs::write(
        &runtime,
        format!(
            "apiVersion: {RUNTIME_CONFIG_API_VERSION}
kind: {RUNTIME_CONFIG_KIND}
identity: {{databaseId: casework-test}}
package: {{root: {package}}}
listener: {{bind: 127.0.0.1:8100, tlsTermination: development-loopback}}
secretProviders: {{file: {{root: {root}/secrets}}, environment: {{}}}}
database: {{runtimeUrlRef: secret:env/RUNTIME, migrationUrlRef: secret:env/MIGRATION}}
authentication: {{oidc: {{issuer: http://127.0.0.1:8091, audience: urn:example:casework}}}}
audit: {{path: {root}/audit.ndjson, hashKeyRef: secret:file/audit}}
sources: {{}}
",
            package = package.display(),
            root = root.display(),
        ),
    )
    .expect("write runtime.yaml");
    runtime
}

#[test]
fn a_refused_project_prints_every_reader_line_to_stderr() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical root");
    let package = root.join("package");
    std::fs::create_dir(&package).expect("package directory");
    let project = PROJECT.replace(
        "    label: Decisions awaiting review\n",
        "    label: Decisions awaiting review\n    lable: Decisions\n",
    ) + "queuez: []\n";
    assert_ne!(project, PROJECT);
    std::fs::write(package.join(POLICY_FILE), &project).expect("write casework.yaml");
    registry_platform_config::write_sum_file(&package, None, &package_limits(), PACKAGE_COMMAND)
        .expect("write SHA256SUMS");
    let runtime = write_runtime(&root, &package);

    let output = Command::new(env!("CARGO_BIN_EXE_casework"))
        .arg("--runtime-config")
        .arg(&runtime)
        .arg("serve")
        .env_remove("CASEWORK_LOG")
        .output()
        .expect("run casework");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    let policy = package.join(POLICY_FILE);
    let label_line = project
        .lines()
        .position(|line| line == "    lable: Decisions")
        .expect("lable line")
        + 1;
    let queuez_line = project.lines().count();
    let expected = format!(
        "casework: the Casework project is invalid
error[config.unknown-key] {policy}:{label_line}:5 /queues/0/lable
  `lable` is not a member of this mapping
  next: Rename `lable` to `label`, or remove it.
error[config.unknown-key] {policy}:{queuez_line}:1 /queuez
  `queuez` is not a member of this mapping
  next: Rename `queuez` to `queues`, or remove it.
2 errors, 0 warnings in 1 file
",
        policy = policy.display(),
    );
    assert_eq!(stderr, expected);
}
