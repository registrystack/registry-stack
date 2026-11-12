// SPDX-License-Identifier: Apache-2.0
//! A scoped capture must keep seeing a diagnostic whose callsite another,
//! unsubscribed test thread reached first. This file holds a single test so
//! no other dispatcher in the binary hides the race.

use registry_platform_testing::CapturedDiagnosticLogs;

fn refuse() {
    tracing::warn!(stage = "header", "refused");
}

#[test]
fn capture_sees_a_callsite_first_reached_by_an_unsubscribed_thread() {
    let captured = CapturedDiagnosticLogs::default();
    let dispatch = captured.subscriber_with_max_level(tracing::Level::DEBUG);

    std::thread::spawn(refuse)
        .join()
        .expect("unsubscribed thread");
    tracing::dispatcher::with_default(&dispatch, refuse);

    assert_eq!(captured.text().lines().count(), 1, "{}", captured.text());
    tracing::dispatcher::with_default(&dispatch, || tracing::debug!("debug capture"));
    assert!(captured.text().contains("\"level\":\"DEBUG\""));
}
