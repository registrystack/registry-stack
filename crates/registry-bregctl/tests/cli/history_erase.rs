// SPDX-License-Identifier: Apache-2.0
//! Offline contract tests for the history erasure acknowledgement. They prove
//! the refusal an operator meets before any file is read or any database
//! connection is opened.

use super::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

struct EraseFixture {
    root: PathBuf,
}

impl EraseFixture {
    fn create() -> Self {
        let root = std::env::current_dir()
            .expect("current directory is available")
            .join(format!(
                "bregctl-history-erase-{}-{}",
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

impl Drop for EraseFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

const REQUEST: &str = r#"{"entityId":"membership-record","recordId":"00000000-0000-4000-8000-000000000001","eraseThroughRevision":2,"operatorReference":"ops-ticket-1","reason":"approved-retention-request"}"#;

fn erase_failure(runtime_config: &Path, request_file: &Path, acknowledge: bool) -> Value {
    let mut arguments = vec![
        "--format",
        "json",
        "history",
        "erase",
        "--runtime-config",
        runtime_config.to_str().expect("path is UTF-8"),
        "--request-file",
        request_file.to_str().expect("path is UTF-8"),
    ];
    if acknowledge {
        arguments.push("--acknowledge-irreversible");
    }
    let output = bregctl(&arguments);
    assert!(!output.status.success(), "{output:?}");
    let report = json_stdout(&output);
    assert_eq!(report["ok"], false);
    assert_eq!(report["command"], "history erase");
    report
}

#[test]
fn erase_refuses_without_the_irreversibility_acknowledgement() {
    let fixture = EraseFixture::create();
    let request = fixture.write_request("request.json", REQUEST, 0o600);

    let report = erase_failure(&fixture.runtime_config(), &request, false);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "history.erase.acknowledgement.required");
    assert_eq!(diagnostic["path"], "acknowledgeIrreversible");
    let message = diagnostic["message"].as_str().expect("message is text");
    assert!(message.contains("--acknowledge-irreversible"), "{message}");
    assert!(message.contains("irreversible"), "{message}");
    assert_tool_diagnostic(diagnostic, "command_arguments", "correct_command_usage");
    assert!(
        !report
            .to_string()
            .contains("00000000-0000-4000-8000-000000000001"),
        "the refusal names no record"
    );
}

#[cfg(unix)]
#[test]
fn erase_refuses_before_reading_an_unsafe_request_file_without_acknowledgement() {
    let fixture = EraseFixture::create();
    let request = fixture.write_request("group-readable.json", REQUEST, 0o644);

    let unacknowledged = erase_failure(&fixture.runtime_config(), &request, false);
    assert_eq!(
        unacknowledged["diagnostics"][0]["code"],
        "history.erase.acknowledgement.required"
    );

    let acknowledged = erase_failure(&fixture.runtime_config(), &request, true);
    assert_eq!(
        acknowledged["diagnostics"][0]["code"],
        "history.erase.request_file.refused"
    );
}
