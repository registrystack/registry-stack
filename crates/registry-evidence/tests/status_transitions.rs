// SPDX-License-Identifier: Apache-2.0

//! Transitions, the observation store, the staleness clock and the mapping
//! version registry, against PostgreSQL. Each test runs in its own schema.

mod status_support;

use std::time::Duration;

use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use proptest::prelude::*;
use registry_evidence::status::{
    transition, CredentialMembers, EntryStatus, MappingRegistration, MappingVersion, Observation,
    ObservationOutcome, Provenance, Refusal, SourceTime, StatusEntry, StatusError, StatusReference,
    Transition, TransitionCause, TransitionOutcome, TransitionRequest,
};
use serde_json::Value;
use status_support::{
    allocate_for, allocate_under, extract_read, http_read, inspector, ledger, mapping_version, now,
    reason, revision, rows, subject, text, TestLedger, MAPPING_BLOCK, OTHER_MAPPING_BLOCK,
    OTHER_REQUIREMENT_ID, REQUIREMENT_ID,
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

/// A request whose hook or reconciliation input the source produced now.
fn request(entry: &StatusEntry, to: EntryStatus, provenance: Provenance) -> TransitionRequest {
    let source_time = match provenance.cause() {
        TransitionCause::Operator => None,
        TransitionCause::Hook | TransitionCause::Reconciliation => Some(SourceTime::new(now())),
    };
    request_at(entry, to, provenance, source_time)
}

fn request_at(
    entry: &StatusEntry,
    to: EntryStatus,
    provenance: Provenance,
    source_time: Option<SourceTime>,
) -> TransitionRequest {
    TransitionRequest {
        entry: entry.clone(),
        to,
        reason: reason("test-category"),
        provenance,
        source_time,
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
            REQUIREMENT_ID,
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
async fn an_input_older_than_the_entry_source_read_less_the_skew_changes_nothing() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let hour = (now() - TimeDelta::hours(3))
        .duration_trunc(TimeDelta::hours(1))
        .unwrap();
    let source_read = hour + TimeDelta::minutes(40);
    let entry = allocate_for(
        &ledger,
        &subject("person-6006"),
        http_read(source_read),
        CredentialMembers::Unbound { count: 1 },
    )
    .await[0]
        .entry()
        .clone();
    let stored: DateTime<Utc> = inspector()
        .await
        .query_one(
            &format!(
                "SELECT source_read_hour FROM \"{}\".allocations WHERE list_id = $1 AND idx = $2",
                ledger.schema
            ),
            &[
                &entry.list_id().as_str(),
                &i32::try_from(entry.idx()).unwrap(),
            ],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, hour);

    let before_skew = Some(SourceTime::new(hour - TimeDelta::minutes(11)));
    let stale = apply(
        &ledger,
        &request_at(&entry, EntryStatus::Invalid, hook(1, 5), before_skew),
    )
    .await
    .unwrap();
    assert_eq!(stale, TransitionOutcome::StaleSource);
    let stale = apply(
        &ledger,
        &request_at(
            &entry,
            EntryStatus::Invalid,
            reconciliation(1, None),
            before_skew,
        ),
    )
    .await
    .unwrap();
    assert_eq!(stale, TransitionOutcome::StaleSource);
    assert_eq!(status_of(&ledger, &entry).await, EntryStatus::Valid);
    assert_eq!(
        allocation_row(&ledger, &entry).await["last_applied_source_revision"],
        Value::Null
    );
    assert!(transition_rows(&ledger).await.is_empty());

    // Older than the exact read, but not than its hour: the stored hour is
    // all the ledger compares with.
    let within_hour = Some(SourceTime::new(hour + TimeDelta::minutes(20)));
    let applied = apply(
        &ledger,
        &request_at(&entry, EntryStatus::Suspended, hook(1, 5), within_hour),
    )
    .await
    .unwrap();
    assert!(
        matches!(applied, TransitionOutcome::Applied { .. }),
        "{applied:?}"
    );
    // Exactly the clock-skew allowance before the hour is not stale.
    let at_skew = Some(SourceTime::new(hour - TimeDelta::minutes(10)));
    let applied = apply(
        &ledger,
        &request_at(
            &entry,
            EntryStatus::Invalid,
            reconciliation(1, None),
            at_skew,
        ),
    )
    .await
    .unwrap();
    assert!(
        matches!(applied, TransitionOutcome::Applied { .. }),
        "{applied:?}"
    );
    assert_eq!(transition_rows(&ledger).await.len(), 2);
}

#[tokio::test]
async fn only_a_hook_or_reconciliation_request_names_a_source_time() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let entry = allocate(&ledger, "person-6007", 1).await[0].entry().clone();
    let source_time = Some(SourceTime::new(now()));
    for invalid in [
        request_at(&entry, EntryStatus::Suspended, operator(), source_time),
        request_at(&entry, EntryStatus::Suspended, hook(1, 2), None),
        request_at(
            &entry,
            EntryStatus::Suspended,
            reconciliation(1, Some(2)),
            None,
        ),
    ] {
        let error = apply(&ledger, &invalid).await.unwrap_err();
        assert!(matches!(error, StatusError::InvalidInput(_)), "{error:?}");
    }
    assert_eq!(status_of(&ledger, &entry).await, EntryStatus::Valid);
    assert!(transition_rows(&ledger).await.is_empty());
}

#[tokio::test]
async fn operator_principals_are_distinct_even_against_a_direct_insert() {
    let ledger = ledger().await;
    let entry = allocate(&ledger, "person-6008", 1).await[0].entry().clone();
    let client = inspector().await;
    let insert = format!(
        "INSERT INTO \"{}\".transitions (transition_id, list_id, idx, from_status, to_status, \
         cause, reason_category, operator_principals, case_reference, occurred_at) \
         VALUES ($1, $2, $3, 0, 2, 'operator', 'test-category', $4, 'case-1', now())",
        ledger.schema
    );
    let idx = i32::try_from(entry.idx()).unwrap();
    let list_id = entry.list_id().as_str();

    let repeated = vec!["operator-a".to_owned(), "operator-a".to_owned()];
    let error = client
        .execute(&insert, &[&Uuid::new_v4(), &list_id, &idx, &repeated])
        .await
        .unwrap_err();
    assert_eq!(error.code().map(|code| code.code()), Some("23514"));

    let distinct = vec!["operator-a".to_owned(), "operator-b".to_owned()];
    client
        .execute(&insert, &[&Uuid::new_v4(), &list_id, &idx, &distinct])
        .await
        .unwrap();
    assert_eq!(transition_rows(&ledger).await.len(), 1);
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
    observe_under(ledger, REQUIREMENT_ID, person, observation).await
}

async fn observe_under(
    ledger: &TestLedger,
    requirement_id: &str,
    person: &str,
    observation: &Observation,
) -> ObservationOutcome {
    ledger
        .ledger
        .record_observation(
            &ledger.reserved,
            requirement_id,
            &subject(person),
            observation,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn the_observation_store_keeps_the_latest_revision_per_requirement_and_pseudonym() {
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
    assert_eq!(row["requirement_id"], REQUIREMENT_ID);
    assert_eq!(row["status"], 0);
    assert_eq!(row["source_revision"], 4);
    assert_eq!(row["pseudonym_key_version"], 1);
    assert_eq!(row["mapping_version"], 1);
}

#[tokio::test]
async fn an_observation_names_its_requirement() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    for requirement_id in [String::new(), "r".repeat(257)] {
        let error = ledger
            .ledger
            .record_observation(
                &ledger.reserved,
                &requirement_id,
                &subject("person-7050"),
                &observation(EntryStatus::Suspended, 1, now()),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, StatusError::InvalidInput(_)), "{error:?}");
    }
    assert!(rows(&inspector().await, &ledger.schema, "observations")
        .await
        .is_empty());
}

#[tokio::test]
async fn a_withdrawal_for_one_requirement_is_not_inherited_by_another() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let read_at = now() - TimeDelta::minutes(30);
    // The subject's record for the other requirement is withdrawn after the
    // source read.
    assert_eq!(
        observe_under(
            &ledger,
            OTHER_REQUIREMENT_ID,
            "person-8200",
            &observation(EntryStatus::Invalid, 2, read_at + TimeDelta::minutes(1)),
        )
        .await,
        ObservationOutcome::Recorded
    );

    // A credential for a requirement whose record was never withdrawn
    // starts VALID and takes no revision from the other record.
    let unaffected = allocate_under(
        &ledger,
        REQUIREMENT_ID,
        &subject("person-8200"),
        http_read(read_at),
        CredentialMembers::Unbound { count: 1 },
    )
    .await;
    let row = allocation_row(&ledger, unaffected[0].entry()).await;
    assert_eq!(row["status"], 0);
    assert_eq!(row["last_applied_source_revision"], Value::Null);
    assert_eq!(row["mapping_version"], Value::Null);

    // A credential for the withdrawn record's requirement inherits it.
    let withdrawn = allocate_under(
        &ledger,
        OTHER_REQUIREMENT_ID,
        &subject("person-8200"),
        http_read(read_at),
        CredentialMembers::Unbound { count: 1 },
    )
    .await;
    let row = allocation_row(&ledger, withdrawn[0].entry()).await;
    assert_eq!(row["status"], 1);
    assert_eq!(row["last_applied_source_revision"], 2);
}

#[tokio::test]
async fn a_newer_revision_for_another_requirement_hides_no_withdrawal() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let read_at = now() - TimeDelta::minutes(30);
    let captured = read_at + TimeDelta::minutes(1);
    // Withdrawn, then the other record changes at a higher revision.
    for (requirement_id, status, source_revision) in [
        (REQUIREMENT_ID, EntryStatus::Invalid, 3),
        (OTHER_REQUIREMENT_ID, EntryStatus::Valid, 7),
    ] {
        assert_eq!(
            observe_under(
                &ledger,
                requirement_id,
                "person-8300",
                &observation(status, source_revision, captured),
            )
            .await,
            ObservationOutcome::Recorded
        );
    }
    // The other record first, then the withdrawal at a lower revision.
    for (requirement_id, status, source_revision) in [
        (OTHER_REQUIREMENT_ID, EntryStatus::Valid, 7),
        (REQUIREMENT_ID, EntryStatus::Invalid, 3),
    ] {
        assert_eq!(
            observe_under(
                &ledger,
                requirement_id,
                "person-8301",
                &observation(status, source_revision, captured),
            )
            .await,
            ObservationOutcome::Recorded
        );
    }
    assert_eq!(
        rows(&inspector().await, &ledger.schema, "observations")
            .await
            .len(),
        4
    );

    // A credential evaluated before the withdrawal inherits it either way.
    for person in ["person-8300", "person-8301"] {
        let references = allocate_under(
            &ledger,
            REQUIREMENT_ID,
            &subject(person),
            http_read(read_at),
            CredentialMembers::Unbound { count: 1 },
        )
        .await;
        let row = allocation_row(&ledger, references[0].entry()).await;
        assert_eq!(row["status"], 1, "{person}");
        assert_eq!(row["last_applied_source_revision"], 3, "{person}");
    }
}

#[tokio::test]
async fn a_revision_of_another_requirement_never_makes_an_input_stale() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let read_at = now() - TimeDelta::minutes(30);
    observe_under(
        &ledger,
        OTHER_REQUIREMENT_ID,
        "person-8400",
        &observation(EntryStatus::Valid, 7, read_at + TimeDelta::minutes(1)),
    )
    .await;
    let entry = allocate_under(
        &ledger,
        REQUIREMENT_ID,
        &subject("person-8400"),
        http_read(read_at),
        CredentialMembers::Unbound { count: 1 },
    )
    .await[0]
        .entry()
        .clone();
    assert_eq!(
        allocation_row(&ledger, &entry).await["last_applied_source_revision"],
        Value::Null
    );

    // Revisions of this requirement's record below the other record's apply.
    let suspended = apply(
        &ledger,
        &request(&entry, EntryStatus::Suspended, hook(1, 4)),
    )
    .await
    .unwrap();
    assert!(
        matches!(suspended, TransitionOutcome::Applied { .. }),
        "{suspended:?}"
    );
    let invalidated = apply(
        &ledger,
        &request(&entry, EntryStatus::Invalid, reconciliation(1, Some(5))),
    )
    .await
    .unwrap();
    assert!(
        matches!(invalidated, TransitionOutcome::Applied { .. }),
        "{invalidated:?}"
    );
    assert_eq!(status_of(&ledger, &entry).await, EntryStatus::Invalid);
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
async fn a_withdrawal_observed_while_the_signer_runs_is_inherited_under_a_repeatable_read_default()
{
    let ledger = status_support::repeatable_read_ledger().await;
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

/// Autocommit writes inherit the session default, and under REPEATABLE READ
/// two writers of the shared open list row fail a snapshot check (40001). The
/// ledger pins READ COMMITTED itself, so every reservation succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reservations_succeed_under_a_repeatable_read_default() {
    let ledger = std::sync::Arc::new(status_support::repeatable_read_ledger().await);
    let mut tasks = Vec::new();
    for worker in 0..8 {
        let ledger = std::sync::Arc::clone(&ledger);
        tasks.push(tokio::spawn(async move {
            for round in 0..25 {
                allocate(&ledger, &format!("person-9{worker}{round:02}"), 1).await;
            }
        }));
    }
    for task in tasks {
        task.await.expect("every reservation succeeds");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_mapping_registrations_succeed_under_a_repeatable_read_default() {
    let ledger = std::sync::Arc::new(status_support::repeatable_read_ledger().await);
    let mut tasks = Vec::new();
    for worker in 1..=8_u32 {
        let ledger = std::sync::Arc::clone(&ledger);
        tasks.push(tokio::spawn(async move {
            for round in 0..10_u32 {
                ledger
                    .ledger
                    .register_mapping_version(&ledger.reserved, mapping_version(worker + round))
                    .await
                    .expect("every registration succeeds");
            }
        }));
    }
    for task in tasks {
        task.await.expect("the registering task joins");
    }
}

#[tokio::test]
async fn a_commit_waits_for_an_observation_being_recorded_and_inherits_it() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let person = subject("person-8150");
    let issued_at = now();
    let fields = registry_evidence::status::AllocationFields {
        requirement_id: REQUIREMENT_ID,
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

    // Another writer holds the subject's pseudonym lock, as hook intake does
    // while it records an observation.
    let writer = inspector().await;
    let key = status_support::pseudonym_lock_key(&status_support::pseudonym_keys(), &person);
    writer.batch_execute("BEGIN").await.unwrap();
    writer
        .execute(
            "SELECT pg_advisory_xact_lock($1, $2)",
            &[&status_support::PSEUDONYM_LOCK_CLASS, &key],
        )
        .await
        .unwrap();
    let commit = transaction.commit();
    tokio::pin!(commit);
    status_support::until_waiting_on_pseudonym_lock(&inspector().await, key, &mut commit).await;

    // The withdrawal lands while the commit waits, then the lock is released.
    let pseudonym = status_support::pseudonym_keys().pseudonym(&person).unwrap();
    writer
        .execute(
            &format!(
                "INSERT INTO \"{}\".observations (requirement_id, selector_pseudonym, \
                 pseudonym_key_version, status, source_revision, captured_at, mapping_version) \
                 VALUES ($1, $2, 1, 1, 2, $3, 1)",
                ledger.schema
            ),
            &[
                &REQUIREMENT_ID,
                &pseudonym.as_bytes().as_slice(),
                &(issued_at + TimeDelta::seconds(1)),
            ],
        )
        .await
        .unwrap();
    writer.batch_execute("COMMIT").await.unwrap();
    commit.await.unwrap();

    let row = allocation_row(&ledger, references[0].entry()).await;
    assert_eq!(row["status"], 1);
    assert_eq!(row["last_applied_source_revision"], 2);
}

/// Hold the advisory lock a process holding only the first pseudonym key
/// takes for `person`, from another session, and return that session and
/// the lock key.
async fn hold_retained_key_lock(person: &str, mode: &str) -> (tokio_postgres::Client, i32) {
    let session = inspector().await;
    let key =
        status_support::pseudonym_lock_key(&status_support::pseudonym_keys(), &subject(person));
    session.batch_execute("BEGIN").await.unwrap();
    session
        .execute(
            &format!("SELECT pg_advisory_xact_lock{mode}($1, $2)"),
            &[&status_support::PSEUDONYM_LOCK_CLASS, &key],
        )
        .await
        .unwrap();
    (session, key)
}

#[tokio::test]
async fn a_commit_under_a_promoted_key_waits_for_an_observation_under_the_retained_key() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let promoted =
        status_support::ledger_on(&ledger.schema, status_support::promoted_pseudonym_keys());
    let person = subject("person-8160");
    let issued_at = now();
    let fields = registry_evidence::status::AllocationFields {
        requirement_id: REQUIREMENT_ID,
        subject: &person,
        issued_at,
        not_after: issued_at + TimeDelta::days(30),
        source_read: http_read(issued_at),
    };
    let mut transaction = promoted
        .begin(&ledger.issuance, Duration::from_secs(20))
        .await
        .unwrap();
    let references = transaction
        .allocate(&fields, CredentialMembers::Unbound { count: 1 })
        .await
        .unwrap();

    // A process not yet holding the promoted key records a withdrawal.
    let (writer, key) = hold_retained_key_lock("person-8160", "").await;
    let commit = transaction.commit();
    tokio::pin!(commit);
    status_support::until_waiting_on_pseudonym_lock(&inspector().await, key, &mut commit).await;
    let pseudonym = status_support::pseudonym_keys().pseudonym(&person).unwrap();
    writer
        .execute(
            &format!(
                "INSERT INTO \"{}\".observations (requirement_id, selector_pseudonym, \
                 pseudonym_key_version, status, source_revision, captured_at, mapping_version) \
                 VALUES ($1, $2, 1, 1, 2, $3, 1)",
                ledger.schema
            ),
            &[
                &REQUIREMENT_ID,
                &pseudonym.as_bytes().as_slice(),
                &(issued_at + TimeDelta::seconds(1)),
            ],
        )
        .await
        .unwrap();
    writer.batch_execute("COMMIT").await.unwrap();
    commit.await.unwrap();
    assert_eq!(
        allocation_row(&ledger, references[0].entry()).await["status"],
        1
    );
}

#[tokio::test]
async fn an_observation_under_a_promoted_key_waits_for_a_commit_under_the_retained_key() {
    let ledger = ledger().await;
    register(&ledger, 1).await;
    let promoted =
        status_support::ledger_on(&ledger.schema, status_support::promoted_pseudonym_keys());

    // A process not yet holding the promoted key is committing an issuance.
    let (issuer, key) = hold_retained_key_lock("person-8170", "_shared").await;
    let person = subject("person-8170");
    let recorded = observation(EntryStatus::Invalid, 2, now());
    let record = promoted.record_observation(&ledger.reserved, REQUIREMENT_ID, &person, &recorded);
    tokio::pin!(record);
    status_support::until_waiting_on_pseudonym_lock(&inspector().await, key, &mut record).await;
    issuer.batch_execute("COMMIT").await.unwrap();
    assert_eq!(record.await.unwrap(), ObservationOutcome::Recorded);
}

#[tokio::test]
async fn the_staleness_clock_holds_the_last_complete_run_observation() {
    let ledger = ledger().await;
    let clock = || async {
        ledger
            .ledger
            .staleness_clock(&ledger.reserved, &[MAPPING_BLOCK])
            .await
            .unwrap()
            .map(|observed| observed.instant())
    };
    assert_eq!(clock().await, None);
    let run = now();
    let published = run - TimeDelta::hours(5);
    ledger
        .ledger
        .advance_staleness_clock(&ledger.reserved, MAPPING_BLOCK, published, run)
        .await
        .unwrap();
    assert_eq!(clock().await, Some(published));

    // An extract dated slightly after the run instant counts from the run.
    let next_run = run + TimeDelta::hours(1);
    ledger
        .ledger
        .advance_staleness_clock(
            &ledger.reserved,
            MAPPING_BLOCK,
            next_run + TimeDelta::minutes(5),
            next_run,
        )
        .await
        .unwrap();
    assert_eq!(clock().await, Some(next_run));

    // An extract dated beyond the skew allowance is refused.
    let error = ledger
        .ledger
        .advance_staleness_clock(
            &ledger.reserved,
            MAPPING_BLOCK,
            next_run + TimeDelta::hours(1),
            next_run,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, StatusError::InvalidInput(_)), "{error:?}");
    assert_eq!(clock().await, Some(next_run));

    // The clock is the last complete run's observation, even when older.
    ledger
        .ledger
        .advance_staleness_clock(&ledger.reserved, MAPPING_BLOCK, published, next_run)
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

async fn clock_of(ledger: &TestLedger, blocks: &[&str]) -> Option<DateTime<Utc>> {
    ledger
        .ledger
        .staleness_clock(&ledger.reserved, blocks)
        .await
        .unwrap()
        .map(|observed| observed.instant())
}

async fn advance_clock(
    ledger: &TestLedger,
    block: &str,
    published: DateTime<Utc>,
    run: DateTime<Utc>,
) {
    ledger
        .ledger
        .advance_staleness_clock(&ledger.reserved, block, published, run)
        .await
        .unwrap();
}

#[tokio::test]
async fn the_publisher_reads_the_oldest_clock_of_its_reconciliation_extracts() {
    let ledger = ledger().await;
    let both = [MAPPING_BLOCK, OTHER_MAPPING_BLOCK];
    let run = now();
    let permits_published = run - TimeDelta::hours(1);
    advance_clock(&ledger, MAPPING_BLOCK, permits_published, run).await;
    assert_eq!(
        clock_of(&ledger, &[MAPPING_BLOCK]).await,
        Some(permits_published)
    );
    // An extract with no complete run yet holds the publisher's clock back.
    assert_eq!(clock_of(&ledger, &both).await, None);

    // The permit extract's publisher breaks; benefit runs keep succeeding.
    for hours in 1..=3 {
        let benefit_run = run + TimeDelta::hours(hours);
        advance_clock(
            &ledger,
            OTHER_MAPPING_BLOCK,
            benefit_run - TimeDelta::minutes(5),
            benefit_run,
        )
        .await;
        assert_eq!(clock_of(&ledger, &both).await, Some(permits_published));
    }
    let later = run + TimeDelta::hours(4);
    advance_clock(
        &ledger,
        MAPPING_BLOCK,
        later - TimeDelta::minutes(20),
        later,
    )
    .await;
    assert_eq!(
        clock_of(&ledger, &both).await,
        Some(run + TimeDelta::hours(3) - TimeDelta::minutes(5))
    );
    assert_eq!(
        rows(&inspector().await, &ledger.schema, "staleness_clock")
            .await
            .len(),
        2
    );

    let error = ledger
        .ledger
        .staleness_clock(&ledger.reserved, &[])
        .await
        .unwrap_err();
    assert!(matches!(error, StatusError::InvalidInput(_)), "{error:?}");
    let error = ledger
        .ledger
        .advance_staleness_clock(&ledger.reserved, "", run, run)
        .await
        .unwrap_err();
    assert!(matches!(error, StatusError::InvalidInput(_)), "{error:?}");
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
