// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::{
    ffi::OsStr,
    process::{Command, ExitCode, Output},
};

struct OwnedRun {
    scratch: tempfile::TempDir,
    project: PathBuf,
    bins: PathBuf,
    report: Value,
}

impl OwnedRun {
    fn new(template: &str) -> Self {
        let scratch = tempfile::tempdir().unwrap();
        let project = scratch.path().join("project with ' spaces");
        assert!(crate::starters::run(&project, template).is_ok());
        Self {
            scratch,
            project,
            bins: PathBuf::from(std::env::var_os("BREG_EXAMPLE_BIN_DIR").unwrap()),
            report: Value::Null,
        }
    }

    fn command(&self, binary: impl AsRef<OsStr>) -> Command {
        let mut command = Command::new(binary);
        command
            .env_remove("REGISTRY_STACK_POSTURE")
            .env_remove("RSTACK_DEV_DATABASE_URL")
            .env_remove("RSTACK_DEV_DATABASE_CA")
            .env("RSTACK_DEV_STATE_DIR", self.scratch.path().join("state"));
        command
    }

    fn dev(&self, args: &[&OsStr]) -> Output {
        self.command(self.bins.join("rstack"))
            .arg("--install-root")
            .arg(self.scratch.path().join("install"))
            .args(["--format", "json", "dev"])
            .args(args)
            .env("RSTACK_BREG_BIN", self.bins.join("breg"))
            .env("RSTACK_BREGCTL_BIN", self.bins.join("bregctl"))
            .output()
            .unwrap()
    }

    fn start(&mut self) {
        let output = self.dev(&[OsStr::new("start"), self.project.as_os_str()]);
        // A failed scenario can leave a ready run. Retain its ID for teardown.
        self.report = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        assert_success(&output);
        assert_eq!(self.report["status"], "ready");
    }

    fn id(&self) -> &str {
        self.report["run_id"].as_str().unwrap()
    }

    fn restart(&mut self) {
        let volume = self.report["database"]["volume"]
            .as_str()
            .unwrap()
            .to_owned();
        let output = self.dev(&[OsStr::new("stop"), OsStr::new(self.id())]);
        assert_success(&output);
        self.start();
        assert_eq!(self.report["database"]["volume"], volume);
    }

    fn restart_after_failed_rehearsal(&mut self) {
        let volume = self.report["database"]["volume"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_success(&self.dev(&[OsStr::new("stop"), OsStr::new(self.id())]));
        let scenario = self.project.join("dev/scenarios.yaml");
        let original = fs::read_to_string(&scenario).unwrap();
        let edited = original.replace("contact@example.test", "different@example.test");
        assert_ne!(original, edited);
        fs::write(&scenario, edited).unwrap();
        let failed = self.dev(&[OsStr::new("start"), self.project.as_os_str()]);
        self.report = serde_json::from_slice(&failed.stdout).unwrap_or(Value::Null);
        fs::write(scenario, original).unwrap();
        assert_eq!(failed.status.code(), Some(1), "{failed:?}");
        assert_eq!(self.report["scenarios"][0]["result"], "failed");
        assert_success(&self.dev(&[OsStr::new("stop"), OsStr::new(self.id())]));
        self.start();
        assert_eq!(self.report["database"]["volume"], volume);
        assert_eq!(self.report["scenarios"][0]["result"], "skipped");
    }

    fn attempts(&self) -> Vec<Attempt> {
        let state = self.report["database"]["developmentState"]
            .as_str()
            .unwrap();
        attempts(&Path::new(state).join("examples")).unwrap()
    }

    fn example(&self, scenario: &str, parent: Option<&str>, interrupt: Option<&str>) -> Value {
        if let Some(step) = interrupt {
            let output = self
                .command(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "examples::recovery_tests::interrupted_example_child",
                    "--nocapture",
                ])
                .env("BREG_EXAMPLE_PROJECT", &self.project)
                .env("BREG_EXAMPLE_RUN_ID", self.id())
                .env("BREG_EXAMPLE_SCENARIO", scenario)
                .env("BREG_EXAMPLE_PARENT", parent.unwrap_or_default())
                .env("BREG_EXAMPLE_TEST_INTERRUPT", step)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(79), "{output:?}");
            return Value::Null;
        }
        let mut command = self.command(self.bins.join("bregctl"));
        command
            .args(["--format", "json", "examples", "run", scenario])
            .arg(&self.project)
            .args(["--run-id", self.id()]);
        if let Some(parent) = parent {
            command.args(["--from-attempt", parent]);
        }
        let output = command.output().unwrap();
        assert_success(&output);
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn contact_count(&self) -> usize {
        let output = self.dev(&[
            OsStr::new("token"),
            OsStr::new(self.id()),
            OsStr::new("--as"),
            OsStr::new("editor"),
        ]);
        assert!(output.status.success(), "failed to mint a synthetic token");
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let path = report["credentials"][0]["header_file"].as_str().unwrap();
        let header = fs::read_to_string(path).unwrap();
        let token = header
            .trim()
            .strip_prefix("Authorization: Bearer ")
            .unwrap();
        let client = example_client(
            self.report["products"]["breg"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            StaticToken::new(token.to_owned()).unwrap(),
        )
        .unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                client
                    .list_records(
                        "contacts",
                        &BRegListRequest::default().options(
                            BRegRecordOptions::default()
                                .access_profile("directory-editor")
                                .unwrap(),
                        ),
                    )
                    .await
                    .unwrap()
                    .value
                    .value
                    .items
                    .len()
            })
    }
}

impl Drop for OwnedRun {
    fn drop(&mut self) {
        if let Some(id) = self.report["run_id"].as_str() {
            let output = self.dev(&[OsStr::new("stop"), OsStr::new(id), OsStr::new("--clean")]);
            if !std::thread::panicking() {
                assert_success(&output);
            }
        }
    }
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "{output:?}");
}

#[test]
#[ignore = "subprocess entry point for the post-commit interruption tests"]
fn interrupted_example_child() {
    let mut arguments = vec![
        "bregctl".into(),
        "--format".into(),
        "json".into(),
        "examples".into(),
        "run".into(),
        std::env::var_os("BREG_EXAMPLE_SCENARIO").unwrap(),
        std::env::var_os("BREG_EXAMPLE_PROJECT").unwrap(),
        "--run-id".into(),
        std::env::var_os("BREG_EXAMPLE_RUN_ID").unwrap(),
    ];
    let parent = std::env::var_os("BREG_EXAMPLE_PARENT").unwrap();
    if !parent.is_empty() {
        arguments.extend(["--from-attempt".into(), parent]);
    }
    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = crate::run_from(arguments, &mut out, &mut err);
    assert_eq!(
        result,
        ExitCode::SUCCESS,
        "{}\n{}",
        String::from_utf8_lossy(&out),
        String::from_utf8_lossy(&err)
    );
    panic!("the post-commit interruption was not reached");
}

#[test]
#[ignore = "requires source-built rstack, breg and bregctl and managed PostgreSQL"]
fn native_create_recovers_after_process_exit_without_duplicate_records() {
    let mut run = OwnedRun::new(crate::starters::DEFAULT_TEMPLATE);
    let input = run.project.join("examples/inputs/contact.json");
    fs::write(
        &input,
        fs::read_to_string(&input)
            .unwrap()
            .replace("contact@example.test", "recovery@example.test"),
    )
    .unwrap();
    run.start();
    let before = run.contact_count();
    run.example("contact", None, Some("create-contact"));
    let [interrupted]: [Attempt; 1] = run.attempts().try_into().ok().unwrap();
    assert!(interrupted.captures.is_empty());
    assert_eq!(interrupted.pending.unwrap().step, "create-contact");
    assert_eq!(run.contact_count(), before + 1);
    run.restart_after_failed_rehearsal();
    assert_eq!(run.contact_count(), before + 1);
    let recovered = run.example("contact", None, None);
    assert_eq!(recovered["attempt"], interrupted.id.to_string());
    let repeated = run.example("contact", None, None);
    assert_eq!(recovered["captures"], repeated["captures"]);
    assert_eq!(run.contact_count(), before + 1);
}

#[test]
#[ignore = "requires source-built rstack, breg and bregctl and managed PostgreSQL"]
fn native_invoke_recovers_original_conditions_after_restart() {
    let mut run = OwnedRun::new(crate::starters::DEFAULT_TEMPLATE);
    run.start();
    run.example("update-contact-email", None, Some("invoke"));
    let [interrupted]: [Attempt; 1] = run.attempts().try_into().ok().unwrap();
    let pending = interrupted.pending.unwrap();
    assert_eq!(pending.step, "invoke");
    let body: Value = serde_json::from_str(pending.capsule["body"].as_str().unwrap()).unwrap();
    assert_eq!(body["preconditions"].as_object().unwrap().len(), 1);
    run.restart();
    let recovered = run.example("update-contact-email", None, None);
    assert_eq!(recovered["attempt"], interrupted.id.to_string());
    let repeated = run.example("update-contact-email", None, None);
    assert_eq!(recovered["captures"], repeated["captures"]);
    assert_eq!(
        recovered["results"]["invoke"],
        repeated["results"]["invoke"]
    );
    assert_eq!(
        recovered["results"]["read-contact"],
        repeated["results"]["read-contact"]
    );
    assert_eq!(
        recovered["results"]["read-contact"]["data"]["domainData"]["email"],
        "new@example.test"
    );
    assert!(run.attempts()[0].pending.is_none());
}

#[test]
#[ignore = "requires source-built rstack, breg and bregctl and managed PostgreSQL"]
fn native_proposal_recovers_start_submit_and_apply_after_restart() {
    let mut run = OwnedRun::new("facility-registry");
    run.start();
    let registered = run.example("register-facility", None, None);
    let parent = registered["attempt"].as_str().unwrap();
    for step in ["start", "submit", "apply"] {
        run.example("deactivate-facility", Some(parent), Some(step));
        let saved = run.attempts();
        let attempt = saved
            .iter()
            .find(|a| a.scenario == "deactivate-facility")
            .unwrap();
        assert_eq!(attempt.pending.as_ref().unwrap().step, step);
        run.restart();
    }
    let recovered = run.example("deactivate-facility", Some(parent), None);
    let repeated = run.example("deactivate-facility", Some(parent), None);
    assert_eq!(recovered["proposals"], repeated["proposals"]);
    assert_eq!(recovered["results"]["apply"], repeated["results"]["apply"]);
    assert_eq!(recovered["results"]["read"], repeated["results"]["read"]);
    assert_eq!(
        recovered["results"]["read"]["data"]["domainData"]["status"],
        "inactive"
    );
    assert!(run
        .attempts()
        .iter()
        .all(|attempt| attempt.pending.is_none()));
}

#[test]
#[ignore = "requires source-built rstack, breg and bregctl and managed PostgreSQL"]
fn live_run_examples_replay_the_same_attempt() {
    let mut run = OwnedRun::new(crate::starters::DEFAULT_TEMPLATE);
    run.start();
    let first = run.example("update-contact-email", None, None);
    let replay = run.example("update-contact-email", None, None);
    assert_eq!(first["attempt"], replay["attempt"]);
    assert_eq!(first["captures"], replay["captures"]);
}

#[test]
fn pending_recovery_only_rebinds_the_owned_loopback_port() {
    let origin = "http://127.0.0.1:28080/";
    let mut pending = Pending {
        step: "create".into(),
        capsule: json!({"source": "http://127.0.0.1:18080/", "body": "original", "key": "original"}),
    };
    let rebound: Value =
        serde_json::from_slice(&pending.recovery_bytes(origin, "/source").unwrap()).unwrap();
    assert_eq!(
        rebound,
        json!({"source": origin, "body": "original", "key": "original"})
    );
    for prior in [
        "https://127.0.0.1:18080/",
        "http://127.0.0.1:18080/other",
        "http://outside.example:18080/",
    ] {
        pending.capsule["source"] = json!(prior);
        assert!(pending.recovery_bytes(origin, "/source").is_err());
    }
}
