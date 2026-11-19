// SPDX-License-Identifier: Apache-2.0

//! The served harness's stderr capture: a line the child writes after the
//! test's last event reaches the shared buffer only once the drain thread
//! has read it, so a presence assertion waits for it instead of reading a
//! snapshot. Needs no database; the child is a shell, not the adapter.
#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/served/mod.rs"]
mod served_harness;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use served_harness::StderrLog;

fn shell(script: &str) -> Child {
    Command::new("sh")
        .arg("-c")
        .arg(script)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the shell starts")
}

fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn a_line_written_after_a_delay_is_found_by_the_wait_and_missed_by_the_snapshot() {
    let mut child = shell("sleep 1; echo marker >&2; sleep 5");
    let log = StderrLog::drain(&mut child);

    assert!(
        !log.snapshot().contains("marker"),
        "the snapshot is taken before the child wrote the line"
    );
    let text = log.wait_for("marker", Duration::from_secs(10));
    assert!(text.contains("marker"), "{text}");

    stop(child);
}

#[test]
fn the_wait_fails_at_its_deadline_with_the_captured_text() {
    let mut child = shell("echo other-line >&2; sleep 5");
    let log = StderrLog::drain(&mut child);
    // The unrelated line is captured before the wait starts, so the failure
    // message must carry it.
    log.wait_for("other-line", Duration::from_secs(10));

    let failure = catch_unwind(AssertUnwindSafe(|| {
        log.wait_for("marker", Duration::from_millis(300))
    }))
    .expect_err("the wait fails when the line never comes");
    let message = failure
        .downcast_ref::<String>()
        .cloned()
        .expect("the wait panics with a formatted message");
    assert!(message.contains("\"marker\""), "{message}");
    assert!(message.contains("300ms"), "{message}");
    assert!(message.contains("other-line"), "{message}");

    stop(child);
}
