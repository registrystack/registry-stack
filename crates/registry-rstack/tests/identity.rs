// SPDX-License-Identifier: Apache-2.0
#![cfg(unix)]

//! `rstack identity generate thunderid` and `rstack identity check`, driven
//! through the built launcher with stub product CLIs.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SECRET: &str = "stub-secret-value-7f3a9c";
const VERSION: &str = registry_platform_buildinfo::DISPLAY_VERSION;

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/platform/examples/identity")
}

/// A scratch directory with a private temp area, the example deployment and
/// its key file, and room for stubs and output.
struct Workspace {
    root: tempfile::TempDir,
}

impl Workspace {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let workspace = Self { root };
        fs::create_dir(workspace.tmp()).unwrap();
        fs::create_dir_all(workspace.path("deployment/keys")).unwrap();
        for file in ["identity-deployment.yaml", "keys/case-portal.jwks.json"] {
            fs::copy(
                examples().join(file),
                workspace.path("deployment").join(file),
            )
            .unwrap();
        }
        workspace
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    fn tmp(&self) -> PathBuf {
        self.path("tmp")
    }

    fn deployment(&self) -> PathBuf {
        self.path("deployment/identity-deployment.yaml")
    }

    /// A stub `bregctl` that reports `version`, records its arguments and the
    /// issuer variable it received, refuses to run when the secret-looking
    /// variable reaches it, and writes the example facts to `--output`.
    fn stub(&self, name: &str, version: &str) -> PathBuf {
        let script = format!(
            "#!/usr/bin/env bash\n\
             set -euo pipefail\n\
             if [[ -n \"${{RSTACK_TEST_SECRET:-}}\" ]]; then echo 'secret reached the driven tool' >&2; exit 9; fi\n\
             if [[ \"${{1:-}}\" == --version ]]; then printf '{name} %s\\n' '{version}'; exit 0; fi\n\
             printf '%s\\n' \"$*\" >> '{log}'\n\
             printf '%s\\n' \"${{RSTACK_TEST_ISSUER:-unset}}\" > '{env}'\n\
             out=''\n\
             while [[ $# -gt 0 ]]; do if [[ \"$1\" == --output ]]; then out=\"$2\"; fi; shift; done\n\
             cp '{facts}' \"$out\"\n",
            log = self.path(&format!("{name}.log")).display(),
            env = self.path(&format!("{name}.env")).display(),
            facts = examples().join("identity-facts.yaml").display(),
        );
        let path = self.path(name);
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn log(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.path(&format!("{name}.log"))).ok()
    }

    fn rstack(&self, arguments: &[&str], bregctl: Option<&Path>) -> Output {
        self.rstack_with(arguments, bregctl, &[])
    }

    /// `rstack` with `extra` variables set in the launcher's environment.
    fn rstack_with(
        &self,
        arguments: &[&str],
        bregctl: Option<&Path>,
        extra: &[(&str, &str)],
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rstack"));
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", self.path("home"))
            .env("TMPDIR", self.tmp())
            .env("RSTACK_TEST_SECRET", SECRET)
            .current_dir(self.root.path())
            .args(arguments);
        // A build that unifies rstack with the product tools links the AWS-LC
        // FIPS library, which Cargo-built binaries find through the directory
        // Cargo supplies to the test process.
        for name in ["DYLD_FALLBACK_LIBRARY_PATH", "LD_LIBRARY_PATH"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        if let Some(bregctl) = bregctl {
            command.env("RSTACK_BREGCTL_BIN", bregctl);
        }
        command.envs(extra.iter().copied());
        command.output().unwrap()
    }

    fn generate(&self, output: &str, bregctl: Option<&Path>) -> Output {
        self.generate_with(output, bregctl, &[])
    }

    fn generate_with(
        &self,
        output: &str,
        bregctl: Option<&Path>,
        extra: &[(&str, &str)],
    ) -> Output {
        let deployment = self.deployment();
        let output = self.path(output);
        let runtime = self.path("breg-runtime.yaml");
        self.rstack_with(
            &[
                "identity",
                "generate",
                "thunderid",
                "--deployment",
                deployment.to_str().unwrap(),
                "--output",
                output.to_str().unwrap(),
                "--breg-project",
                "project-dir",
                "--breg-runtime-config",
                runtime.to_str().unwrap(),
            ],
            bregctl,
            extra,
        )
    }
}

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, directory: &Path, found: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, found);
            } else {
                let relative = path.strip_prefix(root).unwrap().to_string_lossy();
                found.insert(relative.into_owned(), fs::read(&path).unwrap());
            }
        }
    }
    let mut found = BTreeMap::new();
    walk(root, root, &mut found);
    found
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn empty(directory: &Path) -> bool {
    fs::read_dir(directory).unwrap().next().is_none()
}

#[test]
fn generate_writes_the_tree_and_drives_the_product_cli_publicly() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    let run = workspace.generate("out", Some(&stub));
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));

    let files = tree(&workspace.path("out"));
    for expected in [
        "deployment.yaml",
        "identity-receipt.json",
        "registry-schema/agent-type.yaml",
    ] {
        assert!(
            files.contains_key(expected),
            "{expected} in {:?}",
            files.keys()
        );
    }
    assert!(files.keys().any(|name| name.starts_with("resources/")));
    // The tool is driven through its public command, with the operator's
    // arguments and a private output file, and nothing else.
    let log = workspace.log("bregctl").unwrap();
    assert!(
        log.starts_with("generate identity-facts /")
            && log.contains("/project-dir --runtime-config /"),
        "{log}"
    );
    assert!(!log.contains("--production"), "{log}");
}

#[test]
fn relative_operator_paths_reach_the_driven_tool_as_absolute_paths() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    let deployment = workspace.deployment();
    let output = workspace.path("out");
    let run = workspace.rstack(
        &[
            "identity",
            "generate",
            "thunderid",
            "--deployment",
            deployment.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--breg-project",
            "project-dir",
            "--breg-runtime-config",
            "./runtime.yaml",
        ],
        Some(&stub),
    );
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
    let log = workspace.log("bregctl").unwrap();
    let words: Vec<&str> = log.split_whitespace().collect();
    let project = words[2];
    let runtime = words[words
        .iter()
        .position(|word| *word == "--runtime-config")
        .unwrap()
        + 1];
    assert!(
        Path::new(project).is_absolute() && project.ends_with("/project-dir"),
        "{log}"
    );
    assert!(
        Path::new(runtime).is_absolute() && runtime.ends_with("/runtime.yaml"),
        "{log}"
    );
    assert!(!runtime.contains("/./"), "{log}");
}

#[test]
fn production_is_forwarded_only_when_asked() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    let deployment = workspace.deployment();
    let output = workspace.path("out");
    let run = workspace.rstack(
        &[
            "identity",
            "generate",
            "thunderid",
            "--deployment",
            deployment.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--breg-project",
            "project-dir",
            "--breg-runtime-config",
            "runtime.yaml",
            "--breg-production",
        ],
        Some(&stub),
    );
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
    assert!(workspace.log("bregctl").unwrap().contains(" --production"));
}

#[test]
fn no_secret_reaches_the_driven_tool_the_streams_or_the_tree() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    let run = workspace.generate("out", Some(&stub));
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
    assert!(!text(&run.stdout).contains(SECRET));
    assert!(!text(&run.stderr).contains(SECRET));
    for (name, bytes) in tree(&workspace.path("out")) {
        assert!(!text(&bytes).contains(SECRET), "{name}");
    }
    assert!(!workspace.log("bregctl").unwrap().contains(SECRET));
}

#[test]
fn variables_the_runtime_config_substitutes_reach_the_driven_tool_and_no_others() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    let issuer = [("RSTACK_TEST_ISSUER", "https://id.example")];
    // A runtime config that names the issuer variable gets it, and a secret
    // it references only as `secret:env/` stays with the launcher: the stub
    // exits 9 if the secret variable reaches it.
    fs::write(
        workspace.path("breg-runtime.yaml"),
        "issuer: ${RSTACK_TEST_ISSUER}\nsigningKey: secret:env/RSTACK_TEST_SECRET\n",
    )
    .unwrap();
    let run = workspace.generate_with("named", Some(&stub), &issuer);
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
    assert_eq!(
        fs::read_to_string(workspace.path("bregctl.env")).unwrap(),
        "https://id.example\n"
    );
    // A runtime config that does not name it does not get it.
    fs::write(
        workspace.path("breg-runtime.yaml"),
        "issuer: https://id.example\n",
    )
    .unwrap();
    let run = workspace.generate_with("unnamed", Some(&stub), &issuer);
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
    assert_eq!(
        fs::read_to_string(workspace.path("bregctl.env")).unwrap(),
        "unset\n"
    );
}

#[test]
fn the_runtime_configs_values_decide_which_variables_are_forwarded() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    let issuer = [("RSTACK_TEST_ISSUER", "https://id.example")];
    let forwarded = |name: &str, config: &str| {
        fs::write(workspace.path("breg-runtime.yaml"), config).unwrap();
        let run = workspace.generate_with(name, Some(&stub), &issuer);
        assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
        fs::read_to_string(workspace.path("bregctl.env")).unwrap()
    };
    // A name in a comment is not substituted by the loader.
    assert_eq!(
        forwarded(
            "comment",
            "# issuer: ${RSTACK_TEST_ISSUER}\nissuer: x # ${RSTACK_TEST_ISSUER}\n"
        ),
        "unset\n"
    );
    // A YAML-escaped spelling is the same value to the loader.
    assert_eq!(
        forwarded("escaped", "issuer: \"\\u0024{RSTACK_TEST_ISSUER}\"\n"),
        "https://id.example\n"
    );
    // A member the loader refuses to substitute does not forward its name.
    assert_eq!(
        forwarded("reference", "signingKeyRef: ${RSTACK_TEST_ISSUER}\n"),
        "unset\n"
    );
}

#[test]
fn a_runtime_config_that_is_not_a_regular_file_is_not_opened() {
    use std::time::{Duration, Instant};
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    let fifo = workspace.path("breg-runtime.yaml");
    let made = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(made.success());
    // Opening a FIFO for reading waits for a writer. If rstack opens it, this
    // writer ends the wait after the limit and the run takes at least that long.
    let limit = Duration::from_secs(8);
    std::thread::spawn(move || {
        std::thread::sleep(limit);
        let _ = fs::OpenOptions::new().write(true).open(&fifo);
    });
    let started = Instant::now();
    let run = workspace.generate("fifo", Some(&stub));
    assert!(started.elapsed() < limit, "rstack waited on the FIFO");
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
}

#[test]
fn a_symlinked_runtime_config_is_not_read_for_variables() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    let issuer = [("RSTACK_TEST_ISSUER", "https://id.example")];
    // The loader refuses a symlinked runtime config, so rstack does not follow
    // it to find names to forward.
    fs::write(
        workspace.path("real-runtime.yaml"),
        "issuer: ${RSTACK_TEST_ISSUER}\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(
        workspace.path("real-runtime.yaml"),
        workspace.path("breg-runtime.yaml"),
    )
    .unwrap();
    let run = workspace.generate_with("linked", Some(&stub), &issuer);
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
    assert_eq!(
        fs::read_to_string(workspace.path("bregctl.env")).unwrap(),
        "unset\n"
    );
}

#[test]
fn stdout_carries_paths_and_counts_only() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    let run = workspace.generate("out", Some(&stub));
    let stdout = text(&run.stdout);
    assert!(
        stdout.contains(workspace.path("out").to_str().unwrap()),
        "{stdout}"
    );
    assert!(stdout.contains("deployment.yaml"), "{stdout}");
    // Environment variable names are listed in the receipt, not on stdout.
    for name in ["STAFF_PORTAL_CLIENT_SECRET", "OFFICER_ONE_PASSWORD"] {
        assert!(!stdout.contains(name), "{stdout}");
    }
    assert!(stdout.contains("identity-receipt.json"), "{stdout}");
}

#[test]
fn json_report_names_files_and_counts() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    let deployment = workspace.deployment();
    let output = workspace.path("out");
    let run = workspace.rstack(
        &[
            "--format",
            "json",
            "identity",
            "generate",
            "thunderid",
            "--deployment",
            deployment.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--breg-project",
            "project-dir",
            "--breg-runtime-config",
            "runtime.yaml",
        ],
        Some(&stub),
    );
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
    let report: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["command"], "identity generate thunderid");
    assert_eq!(report["status"], "complete");
    assert!(report["files"].as_array().unwrap().len() >= 3);
    assert!(report["machineClients"].is_number());
    assert!(report["requiredEnvironmentCount"].as_u64().unwrap() >= 2);
}

#[test]
fn two_runs_produce_a_byte_identical_tree() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    assert_eq!(
        workspace.generate("first", Some(&stub)).status.code(),
        Some(0)
    );
    assert_eq!(
        workspace.generate("second", Some(&stub)).status.code(),
        Some(0)
    );
    let first = tree(&workspace.path("first"));
    assert!(!first.is_empty());
    assert_eq!(first, tree(&workspace.path("second")));
}

#[test]
fn a_driven_tool_of_another_version_is_refused() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", "0.0.1-other");
    let run = workspace.generate("out", Some(&stub));
    assert_eq!(run.status.code(), Some(1));
    let stderr = text(&run.stderr);
    assert!(stderr.contains("0.0.1-other"), "{stderr}");
    assert!(stderr.contains(VERSION), "{stderr}");
    assert!(workspace.log("bregctl").is_none(), "facts were requested");
    assert!(!workspace.path("out").exists());
    assert!(empty(&workspace.tmp()), "scratch left behind");
}

#[test]
fn an_existing_output_directory_is_refused_before_any_tool_runs() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    fs::create_dir(workspace.path("out")).unwrap();
    fs::write(workspace.path("out/keep.txt"), "mine").unwrap();
    let run = workspace.generate("out", Some(&stub));
    assert_eq!(run.status.code(), Some(1));
    assert!(
        text(&run.stderr).contains("already exists"),
        "{}",
        text(&run.stderr)
    );
    assert!(workspace.log("bregctl").is_none());
    assert_eq!(
        fs::read_to_string(workspace.path("out/keep.txt")).unwrap(),
        "mine"
    );
}

#[test]
fn a_refused_input_leaves_no_output_and_no_scratch() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    fs::remove_file(workspace.path("deployment/keys/case-portal.jwks.json")).unwrap();
    let run = workspace.generate("out", Some(&stub));
    assert_eq!(run.status.code(), Some(1), "{}", text(&run.stderr));
    assert!(text(&run.stderr).contains("missing-key-file"));
    assert!(!workspace.path("out").exists());
    assert!(empty(&workspace.tmp()), "scratch left behind");
}

#[test]
fn a_successful_run_leaves_no_scratch() {
    let workspace = Workspace::new();
    let stub = workspace.stub("bregctl", VERSION);
    assert_eq!(
        workspace.generate("out", Some(&stub)).status.code(),
        Some(0)
    );
    assert!(empty(&workspace.tmp()), "scratch left behind");
}

#[test]
fn a_driven_tool_that_fails_is_reported_with_its_status() {
    let workspace = Workspace::new();
    let stub = workspace.path("bregctl");
    fs::write(
        &stub,
        format!("#!/usr/bin/env bash\nif [[ \"${{1:-}}\" == --version ]]; then echo 'bregctl {VERSION}'; exit 0; fi\necho 'runtime refused' >&2\nexit 1\n"),
    )
    .unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
    let run = workspace.generate("out", Some(&stub));
    assert_eq!(run.status.code(), Some(1));
    let stderr = text(&run.stderr);
    assert!(
        stderr.contains("bregctl") && stderr.contains("runtime refused"),
        "{stderr}"
    );
    assert!(!workspace.path("out").exists());
    assert!(empty(&workspace.tmp()));
}

#[test]
fn a_missing_component_is_refused_with_the_install_command() {
    let workspace = Workspace::new();
    let run = workspace.generate("out", None);
    assert_eq!(run.status.code(), Some(1));
    assert!(
        text(&run.stderr).contains("rstack install breg"),
        "{}",
        text(&run.stderr)
    );
}

#[test]
fn at_least_one_product_input_is_required() {
    let workspace = Workspace::new();
    let deployment = workspace.deployment();
    let output = workspace.path("out");
    let run = workspace.rstack(
        &[
            "identity",
            "generate",
            "thunderid",
            "--deployment",
            deployment.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(run.status.code(), Some(2));
}

#[test]
fn a_product_runtime_config_needs_its_project() {
    let workspace = Workspace::new();
    let deployment = workspace.deployment();
    let output = workspace.path("out");
    let run = workspace.rstack(
        &[
            "identity",
            "generate",
            "thunderid",
            "--deployment",
            deployment.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--casework-runtime-config",
            "runtime.yaml",
        ],
        None,
    );
    assert_eq!(run.status.code(), Some(2));
}

#[test]
fn check_accepts_the_committed_examples() {
    let workspace = Workspace::new();
    for name in ["identity-facts.yaml", "identity-deployment.yaml"] {
        let file = examples().join(name);
        let run = workspace.rstack(&["identity", "check", file.to_str().unwrap()], None);
        assert_eq!(run.status.code(), Some(0), "{name}: {}", text(&run.stdout));
    }
}

#[test]
fn check_refuses_a_bad_file_with_positioned_diagnostics() {
    let workspace = Workspace::new();
    let text_in = fs::read_to_string(examples().join("identity-facts.yaml")).unwrap();
    let file = workspace.path("facts.yaml");
    fs::write(
        &file,
        text_in.replace("issuer: https://id.registry.example", "issuer: nope"),
    )
    .unwrap();
    let run = workspace.rstack(&["identity", "check", file.to_str().unwrap()], None);
    assert_eq!(run.status.code(), Some(1));
    let out = text(&run.stdout);
    assert!(out.contains("error[identity.facts."), "{out}");
    assert!(out.contains("facts.yaml:"), "{out}");
}

#[test]
fn check_reports_json_with_the_shared_envelope() {
    let workspace = Workspace::new();
    let file = workspace.path("facts.yaml");
    fs::write(
        &file,
        "apiVersion: id.registrystack.org/formats/platform/identity-facts/v1\nkind: Wrong\n",
    )
    .unwrap();
    let run = workspace.rstack(
        &[
            "--format",
            "json",
            "identity",
            "check",
            file.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(run.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["status"], "domain-refusal");
    assert!(!report["diagnostics"].as_array().unwrap().is_empty());
    // `serde_json::Value` sorts members, so the order is read from the text.
    let raw = text(&run.stdout);
    let opening =
        r#"{"ok":false,"command":"identity check","status":"domain-refusal","apiVersion":"#;
    assert!(raw.starts_with(opening), "{raw}");
    assert!(raw.contains(r#","kind":"PlatformIdentityReport""#), "{raw}");
}

#[test]
fn check_exits_three_for_an_unreadable_file() {
    let workspace = Workspace::new();
    let file = workspace.path("absent.yaml");
    let run = workspace.rstack(&["identity", "check", file.to_str().unwrap()], None);
    assert_eq!(run.status.code(), Some(3));
}

#[test]
fn check_applies_the_cross_file_rules_given_facts() {
    let workspace = Workspace::new();
    let deployment = workspace.deployment();
    let facts = examples().join("identity-facts.yaml");
    let ok = workspace.rstack(
        &[
            "identity",
            "check",
            deployment.to_str().unwrap(),
            "--facts",
            facts.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(ok.status.code(), Some(0), "{}", text(&ok.stdout));
    let edited = fs::read_to_string(&deployment)
        .unwrap()
        .replace("id: case-portal", "id: other-portal");
    fs::write(&deployment, edited).unwrap();
    let refused = workspace.rstack(
        &[
            "identity",
            "check",
            deployment.to_str().unwrap(),
            "--facts",
            facts.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(refused.status.code(), Some(1));
}

#[test]
fn check_reads_no_secret() {
    let workspace = Workspace::new();
    let deployment = workspace.deployment();
    let run = workspace.rstack(&["identity", "check", deployment.to_str().unwrap()], None);
    assert!(!text(&run.stdout).contains(SECRET));
    assert!(!text(&run.stderr).contains(SECRET));
}
