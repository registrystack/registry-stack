// SPDX-License-Identifier: Apache-2.0

//! The closed words Casework writes for clocks, staffing,
//! paging, directory targets, and caseload moves are kebab-case, and the
//! snake_case spelling of a multi-word value is not read.

use std::fmt::Debug;

use registry_casework_core::{
    ClockRuntimeState, DirectoryTargetPurpose, DirectoryTargetsQuery, PageStatus, ReviewClockState,
    StaffingDiagnostic,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;

fn assert_words<T>(expected: &[(T, &str)])
where
    T: Copy + Debug + DeserializeOwned + PartialEq + Serialize,
{
    for (value, word) in expected {
        assert_eq!(serde_json::to_value(value).unwrap(), *word);
        assert_eq!(serde_json::from_value::<T>(json!(word)).unwrap(), *value);
        if word.contains('-') {
            let previous = word.replace('-', "_");
            assert!(
                serde_json::from_value::<T>(json!(previous)).is_err(),
                "{previous} is not read"
            );
        }
    }
}

#[test]
fn every_clock_state_is_kebab_case() {
    assert_words(&[
        (ClockRuntimeState::Running, "running"),
        (ClockRuntimeState::Completed, "completed"),
        (ClockRuntimeState::Cancelled, "cancelled"),
        (
            ClockRuntimeState::VerificationPending,
            "verification-pending",
        ),
        (
            ClockRuntimeState::SourceFactsMissing,
            "source-facts-missing",
        ),
    ]);
    assert_words(&[
        (ReviewClockState::Running, "running"),
        (ReviewClockState::Completed, "completed"),
        (ReviewClockState::Cancelled, "cancelled"),
        (ReviewClockState::SourceFactsMissing, "source-facts-missing"),
    ]);
}

/// A subject clock covers one request and never pauses, so no clock state
/// reads `paused`.
#[test]
fn no_clock_state_reads_paused() {
    assert!(serde_json::from_value::<ClockRuntimeState>(json!("paused")).is_err());
    assert!(serde_json::from_value::<ReviewClockState>(json!("paused")).is_err());
}

#[test]
fn the_staffing_diagnostic_is_kebab_case() {
    assert_words(&[(StaffingDiagnostic::NoCoverAvailable, "no-cover-available")]);
}

#[test]
fn every_page_status_is_kebab_case() {
    assert_words(&[
        (PageStatus::Complete, "complete"),
        (PageStatus::BudgetExhausted, "budget-exhausted"),
        (PageStatus::SourceUnavailable, "source-unavailable"),
    ]);
}

#[test]
fn every_directory_target_purpose_is_kebab_case() {
    assert_words(&[
        (DirectoryTargetPurpose::Assignment, "assignment"),
        (DirectoryTargetPurpose::AbsencePerson, "absence-person"),
        (DirectoryTargetPurpose::AbsenceCover, "absence-cover"),
    ]);
    for previous in ["absence_person", "absence_cover"] {
        assert!(
            serde_json::from_value::<DirectoryTargetsQuery>(json!({"purpose": previous})).is_err(),
            "a directory target query naming {previous} is refused"
        );
    }
}

#[test]
fn review_and_supervision_staffing_notices_are_optional_and_closed() {
    let notice = json!({
        "taskId": "00000000-0000-4000-8000-000000000001",
        "requestId": "00000000-0000-4000-8000-000000000002",
        "queue": "review", "revision": 1, "state": "open",
        "staffingDiagnostic": "no-cover-available"
    });
    let mut supervisor: registry_casework_core::SupervisoryReviewTask =
        serde_json::from_value(notice.clone()).unwrap();
    assert_eq!(serde_json::to_value(&supervisor).unwrap(), notice);
    supervisor.staffing_diagnostic = None;
    let without = serde_json::to_value(supervisor).unwrap();
    assert!(without.get("staffingDiagnostic").is_none());
    let mut reviewer = notice;
    reviewer.as_object_mut().unwrap().extend(
        json!({
            "subject": {"source": "records", "type": "proposal", "id": "1",
                "version": "1", "digest": format!("sha256:{}", "a".repeat(64))},
            "requesterReference": "REF-1", "deadlineAt": null,
            "createdAt": "2026-10-14T00:00:00Z", "stageIndex": 0,
            "stageId": "review", "eligibleProfiles": ["staff"]
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let mut task: registry_casework_core::ReviewTask =
        serde_json::from_value(reviewer.clone()).unwrap();
    assert_eq!(serde_json::to_value(&task).unwrap(), reviewer);
    task.staffing_diagnostic = None;
    assert!(serde_json::to_value(task)
        .unwrap()
        .get("staffingDiagnostic")
        .is_none());
    reviewer["staffingDiagnostic"] = json!("unknown-cover-state");
    assert!(serde_json::from_value::<registry_casework_core::ReviewTask>(reviewer).is_err());
    let mut invalid_supervision = without;
    invalid_supervision["staffingDiagnostic"] = json!("unknown-cover-state");
    assert!(
        serde_json::from_value::<registry_casework_core::SupervisoryReviewTask>(
            invalid_supervision
        )
        .is_err()
    );
}
