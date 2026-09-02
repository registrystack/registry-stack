// SPDX-License-Identifier: Apache-2.0
//! Offline contract tests for the coverage rebaseline request file. They prove
//! the refusals an operator meets before any database connection is opened.

use super::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

struct RebaselineFixture {
    root: PathBuf,
}

impl RebaselineFixture {
    fn create() -> Self {
        let root = std::env::current_dir()
            .expect("current directory is available")
            .join(format!(
                "registry-serverctl-rebaseline-{}-{}",
                std::process::id(),
                TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&root).expect("test directory is created");
        Self { root }
    }

    fn write_request(&self, name: &str, body: &str, mode: u32) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, body).expect("request file is written");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .expect("request permissions are set");
        let _ = mode;
        path
    }

    fn runtime_config(&self) -> PathBuf {
        self.root.join("runtime.yaml")
    }
}

impl Drop for RebaselineFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn rebaseline_failure(runtime_config: &Path, request_file: &Path) -> Value {
    let output = registry_serverctl(&[
        "--format",
        "json",
        "history",
        "rebaseline",
        "--runtime-config",
        runtime_config.to_str().expect("path is UTF-8"),
        "--request-file",
        request_file.to_str().expect("path is UTF-8"),
    ]);
    assert!(!output.status.success(), "{output:?}");
    let report = json_stdout(&output);
    assert_eq!(report["ok"], false);
    assert_eq!(report["command"], "history rebaseline");
    report
}

#[test]
fn rebaseline_refuses_a_relative_runtime_configuration_path() {
    let fixture = RebaselineFixture::create();
    let request = fixture.write_request(
        "request.json",
        r#"{"operatorReference":"ops-ticket-1"}"#,
        0o600,
    );

    let report = rebaseline_failure(Path::new("runtime.yaml"), &request);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(
        diagnostic["code"],
        "history.rebaseline.runtime_config.path_invalid"
    );
    assert_tool_diagnostic(
        diagnostic,
        "runtime_configuration",
        "correct_runtime_configuration",
    );
}

#[cfg(unix)]
#[test]
fn rebaseline_refuses_a_request_file_other_accounts_can_read() {
    let fixture = RebaselineFixture::create();
    let request = fixture.write_request(
        "group-readable.json",
        r#"{"operatorReference":"ops-ticket-1"}"#,
        0o644,
    );

    let report = rebaseline_failure(&fixture.runtime_config(), &request);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(
        diagnostic["code"],
        "history.rebaseline.request_file.refused"
    );
    assert_tool_diagnostic(
        diagnostic,
        "history_rebaseline",
        "prepare_history_rebaseline_request",
    );
}

#[test]
fn rebaseline_refuses_a_request_document_carrying_erasure_fields() {
    let fixture = RebaselineFixture::create();
    let request = fixture.write_request(
        "erasure-shaped.json",
        r#"{
          "operatorReference":"ops-ticket-1",
          "entityId":"membership",
          "recordId":"018feaa0-68f9-4a45-b9e3-58436df07af7",
          "eraseThroughRevision":1
        }"#,
        0o600,
    );

    let report = rebaseline_failure(&fixture.runtime_config(), &request);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "history.rebaseline.request.refused");
    assert_tool_diagnostic(
        diagnostic,
        "history_rebaseline",
        "prepare_history_rebaseline_request",
    );
}
