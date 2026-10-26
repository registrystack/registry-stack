// SPDX-License-Identifier: Apache-2.0

//! Transitions, the observation store, the staleness clock and the mapping
//! version registry, against PostgreSQL. Each test runs in its own schema.

mod status_support;

use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use proptest::prelude::*;
use registry_evidence::status::{
    transition, CredentialMembers, EntryStatus, MappingRegistration, MappingVersion, Observation,
    ObservationOutcome, Provenance, Refusal, StatusEntry, StatusError, StatusReference, Transition,
    TransitionCause, TransitionOutcome, TransitionRequest,
};
use serde_json::Value;
use status_support::{
    allocate_for, extract_read, http_read, inspector, ledger, mapping_version, now, reason,
    revision, rows, subject, text, TestLedger,
};
use uuid::Uuid;

const ALL_STATUSES: [EntryStatus; 3] = [
    EntryStatus::Valid,
    EntryStatus::Invalid,
    EntryStatus::Suspended,
];
const ALL_CAUSES: [TransitionCause; 3] = [
    TransitionCause::Hook,
    TransitionCause::Operator,
    TransitionCause::Reconciliation,
];

fn hook(mapping: u32, source_revision: i64) -> Provenance {
    Provenance::Hook {
        mapping_version: mapping_version(mapping),
        event_id: text(&Uuid::new_v4().to_string()),
        revision: revision(source_revision),
        package_revision: text(
            "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
        ),
        source: text("urn:example:registry"),
    }
}

fn operator() -> Provenance {
    Provenance::Operator {
        principals: vec![text("operator-a"), text("operator-b")],
        case_reference: text("case-2026-0042"),
    }
}

fn reconciliation(mapping: u32, source_revision: Option<i64>) -> Provenance {
    Provenance::Reconciliation {
        mapping_version: mapping_version(mapping),
        run_id: Uuid::new_v4(),
        extract_digest: [0x3c; 32],
        revision: source_revision.map(revision),
    }
}

fn provenance(cause: TransitionCause, mapping: u32, source_revision: i64) -> Provenance {
    match cause {
        TransitionCause::Hook => hook(mapping, source_revision),
        TransitionCause::Operator => operator(),
        TransitionCause::Reconciliation => reconciliation(mapping, Some(source_revision)),
    }
}

fn request(entry: &StatusEntry, to: EntryStatus, provenance: Provenance) -> TransitionRequest {
    TransitionRequest {
        entry: entry.clone(),
        to,
        reason: reason("test-category"),
        provenance,
    }
}

async fn register(ledger: &TestLedger, version: u32) -> MappingRegistration {
    ledger
        .ledger
        .register_mapping_version(&ledger.reserved, mapping_version(version))
        .await
        .unwrap()
}

async fn allocate(ledger: &TestLedger, person: &str, count: usize) -> Vec<StatusReference> {
    allocate_for(
        ledger,
        &subject(person),
        http_read(now()),
        CredentialMembers::Unbound { count },
    )
    .await
}

async fn status_of(ledger: &TestLedger, entry: &StatusEntry) -> EntryStatus {
    ledger
        .ledger
        .entry_status(&ledger.reserved, entry)
        .await
        .unwrap()
}

async fn apply(
    ledger: &TestLedger,
    request: &TransitionRequest,
) -> Result<TransitionOutcome, StatusError> {
    ledger
        .ledger
        .apply_transition(&ledger.reserved, request)
        .await
}

async fn allocation_row(ledger: &TestLedger, entry: &StatusEntry) -> Value {
    rows(&inspector().await, &ledger.schema, "allocations")
        .await
        .into_iter()
        .find(|row| {
            row["list_id"] == entry.list_id().as_str()
                && row["idx"].as_u64() == Some(u64::from(entry.idx()))
        })
        .unwrap()
}

async fn transition_rows(ledger: &TestLedger) -> Vec<Value> {
    rows(&inspector().await, &ledger.schema, "transitions").await
}

/// Bring a VALID entry to `status` through an operator transition.
async fn bring_to(ledger: &TestLedger, entry: &StatusEntry, status: EntryStatus) {
    if status != EntryStatus::Valid {
        let outcome = apply(ledger, &request(entry, status, operator()))
            .await
            .unwrap();
        assert!(
            matches!(outcome, TransitionOutcome::Applied { .. }),
            "{outcome:?}"
        );
    }
}

#[tokio::test]
async fn every_cell_of_the_transition_table_holds_in_the_ledger() {
    let ledger = ledger().await;
    assert_eq!(register(&ledger, 1).await, MappingRegistration::Current);
    let references = allocate(&ledger, "person-6000", 27).await;
    let mut entries = references.iter().map(|reference| reference.entry().clone());
    let mut source_revision = 1;
    for from in ALL_STATUSES {
        for to in ALL_STATUSES {
            for cause in ALL_CAUSES {
                let entry = entries.next().unwrap();
                bring_to(&ledger, &entry, from).await;
                source_revision += 1;
                let outcome = apply(
                    &ledger,
                    &request(&entry, to, provenance(cause, 1, source_revision)),
                )
                .await
                .unwrap();
                let after = status_of(&ledger, &entry).await;
                match transition(from, to, cause) {
                    Ok(Transition::Change { .. }) => {
                        assert!(
                            matches!(outcome, TransitionOutcome::Applied { from: f, to: t, .. } if f == from && t == to),
                            "{from:?} to {to:?} by {cause:?}: {outcome:?}"
                        );
                        assert_eq!(after, to);
                    }
                    Ok(Transition::Unchanged(status)) => {
                        assert_eq!(outcome, TransitionOutcome::Unchanged(status));
                        assert_eq!(after, from);
                    }
                    Err(refusal) => {
                        assert_eq!(outcome, TransitionOutcome::Refused(refusal));
                        assert_eq!(after, from);
                    }
                }
            }
        }
    }
    // Each operator setup step and each applied cell wrote exactly one row.
    let applied = transition_rows(&ledger).await;
    assert!(applied
        .iter()
        .all(|row| row["from_status"] != i64::from(EntryStatus::Invalid.code())));
}

#[tokio::test]
async fn a_transition_records_the_closed_provenance_of_its_cause() {
    let ledger = ledger().await;
    register(&ledger, 3).await;
    let references = allocate(&ledger, "person-6001", 3).await;
    let [by_hook, by_operator, by_reconciliation] =
        [0, 1, 2].map(|at| references[at].entry().clone());

    let hook_provenance = hook(3, 41);
    let Provenance::Hook { event_id, .. } = &hook_provenance else {
        unreachable!()
    };
    let event_id = event_id.as_str().to_owned();
    let outcome = apply(
        &ledger,
        &request(&by_hook, EntryStatus::Suspended, hook_provenance),
    )
    .await
    .unwrap();
    let TransitionOutcome::Applied { transition_id, .. } = outcome else {
        panic!("{outcome:?}")
    };
    apply(
        &ledger,
        &request(&by_operator, EntryStatus::Invalid, operator()),
    )
    .await
    .unwrap();
    let reconciliation_provenance = reconciliation(3, None);
    let Provenance::Reconciliation { run_id, .. } = &reconciliation_provenance else {
        unreachable!()
    };
    let run_id = *run_id;
    apply(
        &ledger,
        &request(
            &by_reconciliation,
            EntryStatus::Suspended,
            reconciliation_provenance,
        ),
    )
    .await
    .unwrap();

    let stored = transition_rows(&ledger).await;
    assert_eq!(stored.len(), 3);
    let row_for = |entry: &StatusEntry| {
        stored
            .iter()
            .find(|row| {
                row["list_id"] == entry.list_id().as_str()
                    && row["idx"].as_u64() == Some(u64::from(entry.idx()))
            })
            .unwrap()
    };

    let row = row_for(&by_hook);
    assert_eq!(row["transition_id"], transition_id.to_string());
    assert_eq!(row["cause"], "hook");
    assert_eq!(row["from_status"], 0);
    assert_eq!(row["to_status"], 2);
    assert_eq!(row["mapping_version"], 3);
    assert_eq!(row["reason_category"], "test-category");
    assert_eq!(row["event_id"], event_id);
    assert_eq!(row["source_revision"], 41);
    assert_eq!(row["event_source"], "urn:example:registry");
    assert!(row["package_revision"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    for absent in [
        "operator_principals",
        "case_reference",
        "run_id",
        "extract_digest",
    ] {
        assert_eq!(row[absent], Value::Null, "{absent}");
    }
    assert_ne!(row["occurred_at"], Value::Null);

    let row = row_for(&by_operator);
    assert_eq!(row["cause"], "operator");
    assert_eq!(row["to_status"], 1);
    assert_eq!(
        row["operator_principals"],
        serde_json::json!(["operator-a", "operator-b"])
    );
    assert_eq!(row["case_reference"], "case-2026-0042");
    for absent in [
        "mapping_version",
        "event_id",
        "source_revision",
        "package_revision",
        "event_source",
        "run_id",
        "extract_digest",
    ] {
        assert_eq!(row[absent], Value::Null, "{absent}");
    }

    let row = row_for(&by_reconciliation);
    assert_eq!(row["cause"], "reconciliation");
    assert_eq!(row["mapping_version"], 3);
    assert_eq!(row["run_id"], run_id.to_string());
    assert_eq!(row["extract_digest"], format!("\\x{}", "3c".repeat(32)));
    for absent in [
        "event_id",
        "source_revision",
        "package_revision",
        "event_source",
        "operator_principals",
        "case_reference",
    ] {
        assert_eq!(row[absent], Value::Null, "{absent}");
    }

    let hook_row = allocation_row(&ledger, &by_hook).await;
    assert_eq!(hook_row["status"], 2);
    assert_eq!(hook_row["last_applied_source_revision"], 41);
    assert_eq!(hook_row["mapping_version"], 3);
    let operator_row = allocation_row(&ledger, &by_operator).await;
    assert_eq!(operator_row["last_applied_source_revision"], Value::Null);
    assert_eq!(operator_row["mapping_version"], Value::Null);
}

#[tokio::test]
async fn a_revision_older_than_the_last_applied_one_changes_nothing() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let entry = allocate(&ledger, "person-6002", 1).await[0].entry().clone();

    let applied = apply(
        &ledger,
        &request(&entry, EntryStatus::Suspended, hook(1, 5)),
    )
    .await
    .unwrap();
    assert!(
        matches!(applied, TransitionOutcome::Applied { .. }),
        "{applied:?}"
    );
    let stale = apply(&ledger, &request(&entry, EntryStatus::Invalid, hook(1, 4)))
        .await
        .unwrap();
    assert_eq!(stale, TransitionOutcome::StaleRevision);
    let stale = apply(
        &ledger,
        &request(&entry, EntryStatus::Invalid, reconciliation(1, Some(3))),
    )
    .await
    .unwrap();
    assert_eq!(stale, TransitionOutcome::StaleRevision);
    assert_eq!(status_of(&ledger, &entry).await, EntryStatus::Suspended);

    // The current status at a newer revision changes nothing but the revision.
    let unchanged = apply(
        &ledger,
        &request(&entry, EntryStatus::Suspended, hook(1, 9)),
    )
    .await
    .unwrap();
    assert_eq!(
        unchanged,
        TransitionOutcome::Unchanged(EntryStatus::Suspended)
    );
    assert_eq!(
        allocation_row(&ledger, &entry).await["last_applied_source_revision"],
        9
    );
    let stale = apply(&ledger, &request(&entry, EntryStatus::Invalid, hook(1, 8)))
        .await
        .unwrap();
    assert_eq!(stale, TransitionOutcome::StaleRevision);
    assert_eq!(transition_rows(&ledger).await.len(), 1);

    // An operator transition carries no revision and is never stale.
    let operator_outcome = apply(&ledger, &request(&entry, EntryStatus::Invalid, operator()))
        .await
        .unwrap();
    assert!(matches!(
        operator_outcome,
        TransitionOutcome::Applied { .. }
    ));
    assert_eq!(
        allocation_row(&ledger, &entry).await["last_applied_source_revision"],
        9
    );
}

#[tokio::test]
async fn a_process_on_a_lower_mapping_version_applies_nothing() {
    let ledger = ledger().await;
    let entry = allocate(&ledger, "person-6003", 1).await[0].entry().clone();

    // Nothing registered yet: no mapped transition applies.
    let error = apply(
        &ledger,
        &request(&entry, EntryStatus::Suspended, hook(1, 1)),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            error,
            StatusError::MappingVersionNotCurrent { presented: 1 }
        ),
        "{error:?}"
    );

    assert_eq!(register(&ledger, 2).await, MappingRegistration::Current);
    // A process restarting on an older bundle is told it is superseded.
    assert_eq!(
        register(&ledger, 1).await,
        MappingRegistration::Superseded {
            highest: mapping_version(2)
        }
    );
    assert_eq!(
        ledger
            .ledger
            .highest_mapping_version(&ledger.reserved)
            .await
            .unwrap(),
        Some(mapping_version(2))
    );
    for provenance in [hook(1, 2), reconciliation(1, Some(2))] {
        let error = apply(
            &ledger,
            &request(&entry, EntryStatus::Suspended, provenance),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                error,
                StatusError::MappingVersionNotCurrent { presented: 1 }
            ),
            "{error:?}"
        );
        assert!(!error.is_dependency());
    }
    let error = ledger
        .ledger
        .record_observation(
            &ledger.reserved,
            &subject("person-6003"),
            &Observation {
                status: EntryStatus::Suspended,
                revision: revision(2),
                captured_at: now(),
                mapping_version: mapping_version(1),
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            StatusError::MappingVersionNotCurrent { presented: 1 }
        ),
        "{error:?}"
    );
    // Operator transitions use no mapping and stay available.
    let operator_outcome = apply(
        &ledger,
        &request(&entry, EntryStatus::Suspended, operator()),
    )
    .await
    .unwrap();
    assert!(matches!(
        operator_outcome,
        TransitionOutcome::Applied { .. }
    ));

    // A bundle rollback bumps the version, and the process on version 2 stops.
    assert_eq!(register(&ledger, 3).await, MappingRegistration::Current);
    let error = apply(&ledger, &request(&entry, EntryStatus::Invalid, hook(2, 3)))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            StatusError::MappingVersionNotCurrent { presented: 2 }
        ),
        "{error:?}"
    );
    let applied = apply(&ledger, &request(&entry, EntryStatus::Invalid, hook(3, 3)))
        .await
        .unwrap();
    assert!(
        matches!(applied, TransitionOutcome::Applied { .. }),
        "{applied:?}"
    );
    assert_eq!(transition_rows(&ledger).await.len(), 2);
}

#[tokio::test]
async fn invalid_stays_terminal_even_against_a_direct_update() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let entry = allocate(&ledger, "person-6004", 1).await[0].entry().clone();
    apply(&ledger, &request(&entry, EntryStatus::Invalid, hook(1, 1)))
        .await
        .unwrap();
    let refused = apply(&ledger, &request(&entry, EntryStatus::Valid, operator()))
        .await
        .unwrap();
    assert_eq!(refused, TransitionOutcome::Refused(Refusal::Terminal));

    let error = inspector()
        .await
        .execute(
            &format!(
                "UPDATE \"{}\".allocations SET status = 0 WHERE list_id = $1 AND idx = $2",
                ledger.schema
            ),
            &[
                &entry.list_id().as_str(),
                &i32::try_from(entry.idx()).unwrap(),
            ],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code().map(|code| code.code()), Some("23514"));
    assert_eq!(status_of(&ledger, &entry).await, EntryStatus::Invalid);
}

#[tokio::test]
async fn an_unknown_entry_is_reported() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let references = allocate(&ledger, "person-6005", 1).await;
    let missing = StatusEntry::new(
        references[0].list_id().clone(),
        (references[0].idx() + 1) % 1024,
    );
    let error = apply(
        &ledger,
        &request(&missing, EntryStatus::Suspended, operator()),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, StatusError::UnknownEntry), "{error:?}");
    let error = ledger
        .ledger
        .entry_status(&ledger.reserved, &missing)
        .await
        .unwrap_err();
    assert!(matches!(error, StatusError::UnknownEntry), "{error:?}");
}

fn observation(
    status: EntryStatus,
    source_revision: i64,
    captured_at: DateTime<Utc>,
) -> Observation {
    Observation {
        status,
        revision: revision(source_revision),
        captured_at,
        mapping_version: mapping_version(1),
    }
}

async fn observe(
    ledger: &TestLedger,
    person: &str,
    observation: &Observation,
) -> ObservationOutcome {
    ledger
        .ledger
        .record_observation(&ledger.reserved, &subject(person), observation)
        .await
        .unwrap()
}

#[tokio::test]
async fn the_observation_store_keeps_the_latest_revision_per_pseudonym() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let at = now();
    assert_eq!(
        observe(
            &ledger,
            "person-7000",
            &observation(EntryStatus::Suspended, 3, at)
        )
        .await,
        ObservationOutcome::Recorded
    );
    assert_eq!(
        observe(
            &ledger,
            "person-7000",
            &observation(EntryStatus::Invalid, 2, at)
        )
        .await,
        ObservationOutcome::Stale
    );
    assert_eq!(
        observe(
            &ledger,
            "person-7000",
            &observation(EntryStatus::Invalid, 3, at)
        )
        .await,
        ObservationOutcome::Stale
    );
    assert_eq!(
        observe(
            &ledger,
            "person-7000",
            &observation(EntryStatus::Valid, 4, at)
        )
        .await,
        ObservationOutcome::Recorded
    );
    observe(
        &ledger,
        "person-7001",
        &observation(EntryStatus::Invalid, 1, at),
    )
    .await;

    let stored = rows(&inspector().await, &ledger.schema, "observations").await;
    assert_eq!(stored.len(), 2);
    let pseudonym = status_support::pseudonym_keys()
        .pseudonym(&subject("person-7000"))
        .unwrap();
    let hex: String = pseudonym
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let row = stored
        .iter()
        .find(|row| row["selector_pseudonym"] == format!("\\x{hex}"))
        .unwrap();
    assert_eq!(row["status"], 0);
    assert_eq!(row["source_revision"], 4);
    assert_eq!(row["pseudonym_key_version"], 1);
    assert_eq!(row["mapping_version"], 1);
}

#[tokio::test]
async fn observations_are_purged_by_capture_time_after_the_retention() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let at = now();
    observe(
        &ledger,
        "person-7100",
        &observation(EntryStatus::Suspended, 1, at - TimeDelta::days(10)),
    )
    .await;
    observe(
        &ledger,
        "person-7101",
        &observation(EntryStatus::Suspended, 1, at - TimeDelta::days(2)),
    )
    .await;
    let purged = ledger
        .ledger
        .purge_observations(&ledger.reserved, Duration::from_secs(7 * 24 * 60 * 60))
        .await
        .unwrap();
    assert_eq!(purged, 1);
    assert_eq!(
        rows(&inspector().await, &ledger.schema, "observations")
            .await
            .len(),
        1
    );
    let error = ledger
        .ledger
        .purge_observations(&ledger.reserved, Duration::ZERO)
        .await
        .unwrap_err();
    assert!(matches!(error, StatusError::InvalidInput(_)), "{error:?}");
}

#[tokio::test]
async fn a_new_allocation_inherits_a_withdrawal_captured_after_its_source_read() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let read_at = now() - TimeDelta::minutes(30);

    // Captured after the source read: inherited, with its revision.
    observe(
        &ledger,
        "person-8000",
        &observation(EntryStatus::Suspended, 12, read_at + TimeDelta::minutes(1)),
    )
    .await;
    let inherited = allocate_for(
        &ledger,
        &subject("person-8000"),
        http_read(read_at),
        CredentialMembers::Unbound { count: 2 },
    )
    .await;
    for reference in &inherited {
        let row = allocation_row(&ledger, reference.entry()).await;
        assert_eq!(row["status"], 2);
        assert_eq!(row["last_applied_source_revision"], 12);
        assert_eq!(row["mapping_version"], 1);
    }

    // Captured well before the source read, beyond the skew: not inherited.
    observe(
        &ledger,
        "person-8001",
        &observation(EntryStatus::Invalid, 7, read_at - TimeDelta::hours(2)),
    )
    .await;
    let fresh = allocate_for(
        &ledger,
        &subject("person-8001"),
        http_read(read_at),
        CredentialMembers::Unbound { count: 1 },
    )
    .await;
    let row = allocation_row(&ledger, fresh[0].entry()).await;
    assert_eq!(row["status"], 0);
    // The observation still marks which revisions are stale for this entry.
    assert_eq!(row["last_applied_source_revision"], 7);

    // A future-dated publishedAt counts as read at the evaluation instant.
    observe(
        &ledger,
        "person-8002",
        &observation(EntryStatus::Invalid, 3, read_at + TimeDelta::minutes(5)),
    )
    .await;
    let extract = allocate_for(
        &ledger,
        &subject("person-8002"),
        extract_read(read_at + TimeDelta::hours(3), read_at),
        CredentialMembers::Unbound { count: 1 },
    )
    .await;
    assert_eq!(
        allocation_row(&ledger, extract[0].entry()).await["status"],
        1
    );

    // Another pseudonym's observation is never inherited.
    let other = allocate(&ledger, "person-8003", 1).await;
    let row = allocation_row(&ledger, other[0].entry()).await;
    assert_eq!(row["status"], 0);
    assert_eq!(row["last_applied_source_revision"], Value::Null);
    // Inheriting is the initial status, not a transition.
    assert!(transition_rows(&ledger).await.is_empty());
}

#[tokio::test]
async fn a_withdrawal_observed_while_the_signer_runs_is_inherited_at_commit() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let person = subject("person-8100");
    let issued_at = now();
    let fields = registry_evidence::status::AllocationFields {
        requirement_id: status_support::REQUIREMENT_ID,
        subject: &person,
        issued_at,
        not_after: issued_at + TimeDelta::days(30),
        source_read: http_read(issued_at),
    };
    let mut transaction = ledger
        .ledger
        .begin(&ledger.issuance, Duration::from_secs(20))
        .await
        .unwrap();
    let references = transaction
        .allocate(&fields, CredentialMembers::Unbound { count: 1 })
        .await
        .unwrap();
    // A hook for this person lands while the credential is being signed.
    assert_eq!(
        observe(
            &ledger,
            "person-8100",
            &observation(EntryStatus::Invalid, 2, now())
        )
        .await,
        ObservationOutcome::Recorded
    );
    transaction.commit().await.unwrap();
    assert_eq!(
        allocation_row(&ledger, references[0].entry()).await["status"],
        1
    );
}

#[tokio::test]
async fn the_staleness_clock_holds_the_last_complete_run_observation() {
    let ledger = ledger().await;
    let clock = || async {
        ledger
            .ledger
            .staleness_clock(&ledger.reserved)
            .await
            .unwrap()
            .map(|observed| observed.instant())
    };
    assert_eq!(clock().await, None);
    let run = now();
    let published = run - TimeDelta::hours(5);
    ledger
        .ledger
        .advance_staleness_clock(&ledger.reserved, published, run)
        .await
        .unwrap();
    assert_eq!(clock().await, Some(published));

    // An extract dated slightly after the run instant counts from the run.
    let next_run = run + TimeDelta::hours(1);
    ledger
        .ledger
        .advance_staleness_clock(&ledger.reserved, next_run + TimeDelta::minutes(5), next_run)
        .await
        .unwrap();
    assert_eq!(clock().await, Some(next_run));

    // An extract dated beyond the skew allowance is refused.
    let error = ledger
        .ledger
        .advance_staleness_clock(&ledger.reserved, next_run + TimeDelta::hours(1), next_run)
        .await
        .unwrap_err();
    assert!(matches!(error, StatusError::InvalidInput(_)), "{error:?}");
    assert_eq!(clock().await, Some(next_run));

    // The clock is the last complete run's observation, even when older.
    ledger
        .ledger
        .advance_staleness_clock(&ledger.reserved, published, next_run)
        .await
        .unwrap();
    assert_eq!(clock().await, Some(published));
    assert_eq!(
        rows(&inspector().await, &ledger.schema, "staleness_clock")
            .await
            .len(),
        1
    );
}

fn status_strategy() -> impl Strategy<Value = EntryStatus> {
    prop::sample::select(ALL_STATUSES.to_vec())
}

fn cause_strategy() -> impl Strategy<Value = TransitionCause> {
    prop::sample::select(ALL_CAUSES.to_vec())
}

fn concurrent_transitions(writers: Vec<Vec<(EntryStatus, TransitionCause)>>) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let ledger = std::sync::Arc::new(ledger().await);
        register(&ledger, 1).await;
        let entry = allocate(&ledger, "person-9000", 1).await[0].entry().clone();
        let mut handles = Vec::new();
        for (writer, steps) in writers.into_iter().enumerate() {
            let ledger = ledger.clone();
            let entry = entry.clone();
            handles.push(tokio::spawn(async move {
                let mut outcomes = Vec::new();
                for (step, (to, cause)) in steps.into_iter().enumerate() {
                    let source_revision = i64::try_from(writer * 1000 + step + 1).unwrap();
                    let outcome = apply(
                        &ledger,
                        &request(&entry, to, provenance(cause, 1, source_revision)),
                    )
                    .await
                    .unwrap();
                    outcomes.push(outcome);
                }
                outcomes
            }));
        }
        let mut outcomes = Vec::new();
        for handle in handles {
            outcomes.extend(handle.await.unwrap());
        }
        let applied: Vec<(EntryStatus, EntryStatus)> = outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                TransitionOutcome::Applied { from, to, .. } => Some((*from, *to)),
                _ => None,
            })
            .collect();
        assert!(applied
            .iter()
            .all(|(from, _)| *from != EntryStatus::Invalid));
        let invalidations = applied
            .iter()
            .filter(|(_, to)| *to == EntryStatus::Invalid)
            .count();
        assert!(invalidations <= 1, "INVALID was entered twice");
        let last = status_of(&ledger, &entry).await;
        assert_eq!(last == EntryStatus::Invalid, invalidations == 1);
        let stored = transition_rows(&ledger).await;
        assert_eq!(stored.len(), applied.len());
        assert!(stored
            .iter()
            .all(|row| row["from_status"] != i64::from(EntryStatus::Invalid.code())));
    });
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

    #[test]
    fn no_sequence_of_transitions_from_any_cause_leaves_invalid(
        writers in prop::collection::vec(
            prop::collection::vec((status_strategy(), cause_strategy()), 1..10),
            1..4,
        ),
    ) {
        concurrent_transitions(writers);
    }
}

#[test]
fn mapping_versions_and_revisions_refuse_values_the_ledger_cannot_store() {
    assert!(MappingVersion::new(0).is_err());
    assert!(MappingVersion::new(u32::try_from(i32::MAX).unwrap()).is_ok());
    assert!(MappingVersion::new(u32::try_from(i32::MAX).unwrap() + 1).is_err());
    assert!(registry_evidence::status::SourceRevision::new(0).is_err());
    assert!(registry_evidence::status::SourceRevision::new(-1).is_err());
    assert!(registry_evidence::status::SourceRevision::new(i64::MAX).is_ok());
}
