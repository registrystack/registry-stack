// SPDX-License-Identifier: Apache-2.0

//! The closed words Casework writes for clocks, staffing, inbox views,
//! paging, directory targets, and caseload moves are kebab-case, and the
//! snake_case spelling of a multi-word value is not read.

use std::fmt::Debug;

use registry_casework_core::{
    CaseloadItemOutcome, ClockRuntimeState, DirectoryTargetPurpose, DirectoryTargetsQuery,
    InboxView, ListWorkItemsQuery, PageStatus, ReviewClockState, StaffingDiagnostic,
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
        (ClockRuntimeState::Paused, "paused"),
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
        (ReviewClockState::Paused, "paused"),
        (ReviewClockState::Completed, "completed"),
        (ReviewClockState::Cancelled, "cancelled"),
        (ReviewClockState::SourceFactsMissing, "source-facts-missing"),
    ]);
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
fn every_caseload_item_outcome_is_kebab_case() {
    assert_words(&[
        (CaseloadItemOutcome::Moved, "moved"),
        (CaseloadItemOutcome::NotVisible, "not-visible"),
        (CaseloadItemOutcome::NotEligible, "not-eligible"),
        (
            CaseloadItemOutcome::AttemptInProgress,
            "attempt-in-progress",
        ),
        (CaseloadItemOutcome::Conflict, "conflict"),
    ]);
}

#[test]
fn every_inbox_view_is_kebab_case() {
    assert_words(&[
        (InboxView::Mine, "mine"),
        (InboxView::MyTeams, "my-teams"),
        (InboxView::TeamHoldings, "team-holdings"),
        (InboxView::Overdue, "overdue"),
        (InboxView::CompletedByMe, "completed-by-me"),
    ]);
    for previous in ["my_teams", "team_holdings", "completed_by_me"] {
        assert!(
            serde_json::from_value::<ListWorkItemsQuery>(json!({"view": previous})).is_err(),
            "a list query naming {previous} is refused"
        );
    }
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
