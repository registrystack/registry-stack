// SPDX-License-Identifier: Apache-2.0

//! Status list allocation inside a caller-held issuance transaction, against
//! PostgreSQL. Each test runs in its own schema.

mod status_support;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use proptest::prelude::*;
use registry_evidence::status::{
    AllocationFields, CredentialMembers, EntryStatus, StatusError, StatusReference,
    STATUS_LIST_ENTRY_COUNT,
};
use serde_json::Value;
use status_support::{
    days, holder_digest_keys, http_read, inspector, ledger, ledger_with, now, pseudonym_keys,
    pseudonym_lock_key, rows, small_list_ledger, subject, thumbprint, TestLedger,
    PSEUDONYM_LOCK_CLASS, PUBLIC_ORIGIN, REQUIREMENT_ID,
};

const DEADLINE: Duration = Duration::from_secs(20);
// Long enough that a loaded machine still finishes a test's setup inside it;
// the deadline tests wait past it by a fixed margin instead.
const SETUP_DEADLINE: Duration = Duration::from_secs(3);
const LONG_AGE: Duration = Duration::from_secs(24 * 60 * 60);

fn hex(bytes: &[u8]) -> String {
    let mut text = String::from("\\x");
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

async fn allocate(
    ledger: &TestLedger,
    person: &str,
    members: CredentialMembers<'_>,
) -> Result<Vec<StatusReference>, StatusError> {
    let subject = subject(person);
    let issued_at = now();
    let fields = AllocationFields {
        requirement_id: REQUIREMENT_ID,
        subject: &subject,
        issued_at,
        not_after: issued_at + days(30),
        source_read: http_read(issued_at),
    };
    let mut transaction = ledger.ledger.begin(&ledger.issuance, DEADLINE).await?;
    let references = transaction.allocate(&fields, members).await?;
    transaction.commit().await?;
    Ok(references)
}

async fn allocation_rows(ledger: &TestLedger) -> Vec<Value> {
    rows(&inspector().await, &ledger.schema, "allocations").await
}

async fn list_rows(ledger: &TestLedger) -> Vec<Value> {
    rows(&inspector().await, &ledger.schema, "lists").await
}

#[tokio::test]
async fn a_committed_transaction_leaves_exactly_the_allocated_rows() {
    let ledger = ledger().await;
    let person = subject("person-0001");
    let issued_at = now();
    let fields = AllocationFields {
        requirement_id: REQUIREMENT_ID,
        subject: &person,
        issued_at,
        not_after: issued_at + days(30),
        source_read: http_read(issued_at),
    };
    let holders = [thumbprint(0x0a), thumbprint(0x0b)];

    let mut transaction = ledger
        .ledger
        .begin(&ledger.issuance, DEADLINE)
        .await
        .unwrap();
    let references = transaction
        .allocate(&fields, CredentialMembers::HolderBound(&holders))
        .await
        .unwrap();
    // The signer runs here, inside the transaction.
    transaction.commit().await.unwrap();

    assert_eq!(references.len(), 2);
    let list_id = references[0].list_id().as_str().to_owned();
    assert_eq!(list_id.len(), 22);
    assert!(list_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
    for reference in &references {
        assert_eq!(
            reference.list_id().as_str(),
            list_id,
            "a batch shares one list"
        );
        assert_eq!(
            reference.uri(),
            format!("{PUBLIC_ORIGIN}/status/v1/lists/{list_id}")
        );
        assert!(reference.idx() < STATUS_LIST_ENTRY_COUNT);
    }
    assert_ne!(references[0].idx(), references[1].idx());

    let pseudonym = pseudonym_keys().pseudonym(&person).unwrap();
    let digests: Vec<_> = holders
        .iter()
        .map(|holder| hex(holder_digest_keys().digest(holder).as_bytes()))
        .collect();
    let stored = allocation_rows(&ledger).await;
    assert_eq!(stored.len(), 2);
    let by_index: BTreeMap<u64, &Value> = stored
        .iter()
        .map(|row| (row["idx"].as_u64().unwrap(), row))
        .collect();
    for (reference, digest) in references.iter().zip(&digests) {
        let row = by_index[&u64::from(reference.idx())];
        assert_eq!(row["list_id"], list_id.as_str());
        assert_eq!(row["requirement_id"], REQUIREMENT_ID);
        assert_eq!(
            row["selector_pseudonym"],
            hex(pseudonym.as_bytes()).as_str()
        );
        assert_eq!(row["pseudonym_key_version"], 1);
        assert_eq!(row["holder_key_digest"], digest.as_str());
        assert_eq!(row["holder_digest_key_version"], 1);
        assert_eq!(row["status"], i64::from(EntryStatus::Valid.code()));
        assert_eq!(row["last_applied_source_revision"], Value::Null);
        assert_eq!(row["mapping_version"], Value::Null);
    }

    let lists = list_rows(&ledger).await;
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0]["list_id"], list_id.as_str());
    assert_eq!(lists[0]["entry_count"], STATUS_LIST_ENTRY_COUNT);
    assert_eq!(lists[0]["bits"], 2);
    assert_eq!(lists[0]["closed_at"], Value::Null);
    assert_eq!(lists[0]["allocated_count"], 2);
}

#[tokio::test]
async fn unbound_members_carry_no_holder_digest() {
    let ledger = ledger().await;
    let references = allocate(
        &ledger,
        "person-0002",
        CredentialMembers::Unbound { count: 3 },
    )
    .await
    .unwrap();
    assert_eq!(references.len(), 3);
    let indices: BTreeSet<u32> = references.iter().map(StatusReference::idx).collect();
    assert_eq!(indices.len(), 3);
    for row in allocation_rows(&ledger).await {
        assert_eq!(row["holder_key_digest"], Value::Null);
        assert_eq!(row["holder_digest_key_version"], Value::Null);
    }
}

#[tokio::test]
async fn a_signer_that_outlives_the_deadline_leaves_no_row() {
    let ledger = ledger().await;
    let person = subject("person-0003");
    let issued_at = now();
    let fields = AllocationFields {
        requirement_id: REQUIREMENT_ID,
        subject: &person,
        issued_at,
        not_after: issued_at + days(30),
        source_read: http_read(issued_at),
    };
    let mut transaction = ledger
        .ledger
        .begin(&ledger.issuance, SETUP_DEADLINE)
        .await
        .unwrap();
    transaction
        .allocate(&fields, CredentialMembers::Unbound { count: 2 })
        .await
        .unwrap();
    // A fake signer that sleeps past the deadline.
    tokio::time::sleep(SETUP_DEADLINE + Duration::from_secs(1)).await;
    let error = transaction.commit().await.unwrap_err();

    assert!(matches!(error, StatusError::DeadlineExceeded), "{error:?}");
    assert!(error.is_dependency());
    assert!(allocation_rows(&ledger).await.is_empty());
    // The pool still serves the next issuance.
    allocate(
        &ledger,
        "person-0003",
        CredentialMembers::Unbound { count: 1 },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn a_dropped_transaction_rolls_back() {
    let ledger = ledger().await;
    let person = subject("person-0004");
    let issued_at = now();
    let fields = AllocationFields {
        requirement_id: REQUIREMENT_ID,
        subject: &person,
        issued_at,
        not_after: issued_at + days(30),
        source_read: http_read(issued_at),
    };
    {
        let mut transaction = ledger
            .ledger
            .begin(&ledger.issuance, DEADLINE)
            .await
            .unwrap();
        transaction
            .allocate(&fields, CredentialMembers::Unbound { count: 2 })
            .await
            .unwrap();
        // A signer failure returns early and drops the transaction.
    }
    // The dropped session is closed, not returned to the pool mid-transaction.
    for _ in 0..50 {
        if allocation_rows(&ledger).await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(allocation_rows(&ledger).await.is_empty());
    let references = allocate(
        &ledger,
        "person-0004",
        CredentialMembers::Unbound { count: 1 },
    )
    .await
    .unwrap();
    assert_eq!(allocation_rows(&ledger).await.len(), 1);
    assert_eq!(references.len(), 1);
}

#[tokio::test]
async fn the_server_ends_a_session_idle_in_transaction_past_deadline_plus_five_seconds() {
    let application_name = format!("status-idle-{}", uuid::Uuid::new_v4().simple());
    let ledger = ledger_with(
        registry_evidence::status::ListPolicy::new(LONG_AGE).unwrap(),
        pseudonym_keys(),
        holder_digest_keys(),
        Some(&application_name),
    )
    .await;
    let person = subject("person-0005");
    let issued_at = now();
    let fields = AllocationFields {
        requirement_id: REQUIREMENT_ID,
        subject: &person,
        issued_at,
        not_after: issued_at + days(30),
        source_read: http_read(issued_at),
    };
    let mut transaction = ledger
        .ledger
        .begin(&ledger.issuance, SETUP_DEADLINE)
        .await
        .unwrap();
    transaction
        .allocate(&fields, CredentialMembers::Unbound { count: 1 })
        .await
        .unwrap();
    // The server counts idle time from the session's last statement.
    let idle_since = tokio::time::Instant::now();

    let inspector = inspector().await;
    let idle_sessions = || async {
        inspector
            .query_one(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE application_name = $1 AND state = 'idle in transaction'",
                &[&application_name],
            )
            .await
            .unwrap()
            .get::<_, i64>(0)
    };
    // Past the deadline, the server still lets the session sit idle.
    tokio::time::sleep_until(idle_since + SETUP_DEADLINE + Duration::from_secs(1)).await;
    assert_eq!(
        idle_sessions().await,
        1,
        "the session is still idle in transaction past the deadline"
    );
    // A process stalled in its signer holds the transaction: the server ends
    // it at the deadline plus five seconds. Poll with a bound that leaves a
    // loaded server's timer lag room.
    let mut idle = 1;
    for _ in 0..50 {
        idle = idle_sessions().await;
        if idle == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(idle, 0, "the server ended the session");

    let error = transaction.commit().await.unwrap_err();
    assert!(error.is_dependency());
    assert!(allocation_rows(&ledger).await.is_empty());
}

#[tokio::test]
async fn a_lock_wait_past_the_deadline_ends_with_the_deadline() {
    let application_name = format!("status-lock-{}", uuid::Uuid::new_v4().simple());
    let ledger = ledger_with(
        registry_evidence::status::ListPolicy::new(LONG_AGE).unwrap(),
        pseudonym_keys(),
        holder_digest_keys(),
        Some(&application_name),
    )
    .await;
    let person = subject("person-0006");
    let key = pseudonym_lock_key(&pseudonym_keys(), &person);
    // An observation being recorded for the subject holds its lock.
    let mut holder = inspector().await;
    let held = holder.transaction().await.unwrap();
    held.execute(
        "SELECT pg_advisory_xact_lock($1, $2)",
        &[&PSEUDONYM_LOCK_CLASS, &key],
    )
    .await
    .unwrap();

    let issued_at = now();
    let fields = AllocationFields {
        requirement_id: REQUIREMENT_ID,
        subject: &person,
        issued_at,
        not_after: issued_at + days(30),
        source_read: http_read(issued_at),
    };
    let mut transaction = ledger
        .ledger
        .begin(&ledger.issuance, SETUP_DEADLINE)
        .await
        .unwrap();
    transaction
        .allocate(&fields, CredentialMembers::Unbound { count: 1 })
        .await
        .unwrap();
    let error = transaction.commit().await.unwrap_err();
    assert!(matches!(error, StatusError::DeadlineExceeded), "{error:?}");

    // The discarded session stops waiting at the deadline instead of holding
    // its uncommitted entries until the lock is released.
    let observer = inspector().await;
    let mut waiting = -1;
    for _ in 0..30 {
        waiting = observer
            .query_one(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE application_name = $1 AND wait_event_type = 'Lock'",
                &[&application_name],
            )
            .await
            .unwrap()
            .get::<_, i64>(0);
        if waiting == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(waiting, 0, "a discarded session still waits on the lock");
    held.rollback().await.unwrap();
    assert!(allocation_rows(&ledger).await.is_empty());
}

#[tokio::test]
async fn a_list_closes_at_half_fill_and_the_next_list_has_a_fresh_id() {
    let ledger = small_list_ledger(8, LONG_AGE).await;
    let mut first_list = None;
    for person in 0..4 {
        let references = allocate(
            &ledger,
            &format!("person-1{person:03}"),
            CredentialMembers::Unbound { count: 1 },
        )
        .await
        .unwrap();
        let list_id = references[0].list_id().as_str().to_owned();
        assert!(references[0].idx() < 8);
        assert_eq!(first_list.get_or_insert(list_id.clone()), &list_id);
    }
    let first_list = first_list.unwrap();
    let references = allocate(
        &ledger,
        "person-1004",
        CredentialMembers::Unbound { count: 1 },
    )
    .await
    .unwrap();
    let second_list = references[0].list_id().as_str().to_owned();
    assert_ne!(second_list, first_list);

    let lists = list_rows(&ledger).await;
    assert_eq!(lists.len(), 2);
    let first = lists
        .iter()
        .find(|row| row["list_id"] == first_list.as_str())
        .unwrap();
    let second = lists
        .iter()
        .find(|row| row["list_id"] == second_list.as_str())
        .unwrap();
    assert_ne!(
        first["closed_at"],
        Value::Null,
        "the half-full list is closed"
    );
    assert_eq!(first["allocated_count"], 4);
    assert_eq!(second["closed_at"], Value::Null);
    assert_eq!(second["allocated_count"], 1);
    assert_eq!(second["entry_count"], 8);
}

#[tokio::test]
async fn a_batch_stays_on_one_list_and_never_fills_it_past_half() {
    let ledger = small_list_ledger(8, LONG_AGE).await;
    let first = allocate(
        &ledger,
        "person-2000",
        CredentialMembers::Unbound { count: 2 },
    )
    .await
    .unwrap();
    let batch = allocate(
        &ledger,
        "person-2001",
        CredentialMembers::Unbound { count: 3 },
    )
    .await
    .unwrap();
    let batch_list = batch[0].list_id().as_str();
    assert!(batch
        .iter()
        .all(|reference| reference.list_id().as_str() == batch_list));
    assert_ne!(batch_list, first[0].list_id().as_str());

    let error = allocate(
        &ledger,
        "person-2002",
        CredentialMembers::Unbound { count: 5 },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, StatusError::BatchTooLarge { requested: 5 }),
        "{error:?}"
    );
    assert!(!error.is_dependency());
}

#[tokio::test]
async fn a_list_closes_at_its_configured_age() {
    let ledger = small_list_ledger(1024, Duration::from_millis(300)).await;
    let first = allocate(
        &ledger,
        "person-3000",
        CredentialMembers::Unbound { count: 1 },
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let second = allocate(
        &ledger,
        "person-3001",
        CredentialMembers::Unbound { count: 1 },
    )
    .await
    .unwrap();
    assert_ne!(first[0].list_id(), second[0].list_id());
    let lists = list_rows(&ledger).await;
    assert_eq!(
        lists
            .iter()
            .filter(|row| row["closed_at"] == Value::Null)
            .count(),
        1
    );
}

#[tokio::test]
async fn allocation_refuses_inputs_it_cannot_store() {
    let ledger = ledger().await;
    let person = subject("person-4000");
    let issued_at = now();
    let valid = AllocationFields {
        requirement_id: REQUIREMENT_ID,
        subject: &person,
        issued_at,
        not_after: issued_at + days(30),
        source_read: http_read(issued_at),
    };
    let cases = [
        (
            AllocationFields {
                requirement_id: "",
                ..valid.clone()
            },
            CredentialMembers::Unbound { count: 1 },
        ),
        (
            AllocationFields {
                not_after: issued_at,
                ..valid.clone()
            },
            CredentialMembers::Unbound { count: 1 },
        ),
        (valid.clone(), CredentialMembers::Unbound { count: 0 }),
        (valid.clone(), CredentialMembers::HolderBound(&[])),
    ];
    for (fields, members) in cases {
        let mut transaction = ledger
            .ledger
            .begin(&ledger.issuance, DEADLINE)
            .await
            .unwrap();
        let error = transaction.allocate(&fields, members).await.unwrap_err();
        assert!(matches!(error, StatusError::InvalidInput(_)), "{error:?}");
        assert!(!error.is_dependency());
    }
    assert!(allocation_rows(&ledger).await.is_empty());
}

#[tokio::test]
async fn one_transaction_allocates_once() {
    let ledger = ledger().await;
    let person = subject("person-5000");
    let issued_at = now();
    let fields = AllocationFields {
        requirement_id: REQUIREMENT_ID,
        subject: &person,
        issued_at,
        not_after: issued_at + days(30),
        source_read: http_read(issued_at),
    };
    let mut transaction = ledger
        .ledger
        .begin(&ledger.issuance, DEADLINE)
        .await
        .unwrap();
    transaction
        .allocate(&fields, CredentialMembers::Unbound { count: 1 })
        .await
        .unwrap();
    let error = transaction
        .allocate(&fields, CredentialMembers::Unbound { count: 1 })
        .await
        .unwrap_err();
    assert!(matches!(error, StatusError::AlreadyAllocated), "{error:?}");
    transaction.commit().await.unwrap();
    assert_eq!(allocation_rows(&ledger).await.len(), 1);
}

#[tokio::test]
async fn migration_is_repeatable_and_refuses_a_newer_schema() {
    let ledger = ledger().await;
    ledger.ledger.migrate(&ledger.reserved).await.unwrap();
    let inspector = inspector().await;
    inspector
        .execute(
            &format!(
                "INSERT INTO \"{}\".schema_migrations (version, applied_at) VALUES (9999, now())",
                ledger.schema
            ),
            &[],
        )
        .await
        .unwrap();
    let error = ledger.ledger.migrate(&ledger.reserved).await.unwrap_err();
    assert!(matches!(error, StatusError::SchemaVersion), "{error:?}");
}

fn concurrent_allocations(tasks: usize, batch: usize, entry_count: u32) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let ledger = std::sync::Arc::new(small_list_ledger(entry_count, LONG_AGE).await);
        let mut handles = Vec::new();
        for task in 0..tasks {
            let ledger = ledger.clone();
            handles.push(tokio::spawn(async move {
                let person = subject(&format!("person-{task:04}"));
                let issued_at = now();
                let fields = AllocationFields {
                    requirement_id: REQUIREMENT_ID,
                    subject: &person,
                    issued_at,
                    not_after: issued_at + days(30),
                    source_read: http_read(issued_at),
                };
                let mut transaction = ledger
                    .ledger
                    .begin(&ledger.issuance, DEADLINE)
                    .await
                    .unwrap();
                let references = transaction
                    .allocate(&fields, CredentialMembers::Unbound { count: batch })
                    .await
                    .unwrap();
                // Hold the transaction across a short signer call.
                tokio::time::sleep(Duration::from_millis(5)).await;
                transaction.commit().await.unwrap();
                references
            }));
        }
        let mut entries = BTreeSet::new();
        for handle in handles {
            for reference in handle.await.unwrap() {
                assert!(reference.idx() < entry_count);
                assert!(
                    entries.insert((reference.list_id().as_str().to_owned(), reference.idx())),
                    "two credentials share one entry"
                );
            }
        }
        assert_eq!(entries.len(), tasks * batch);
        let stored = allocation_rows(&ledger).await;
        assert_eq!(stored.len(), tasks * batch);
        let lists = list_rows(&ledger).await;
        assert_eq!(
            lists
                .iter()
                .filter(|row| row["closed_at"] == Value::Null)
                .count(),
            1
        );
        for list in &lists {
            let list_id = list["list_id"].as_str().unwrap();
            let used = entries.iter().filter(|(id, _)| id == list_id).count();
            assert!(used as u32 <= entry_count / 2, "a list filled past half");
        }
    });
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]

    #[test]
    fn concurrent_allocations_never_share_an_entry(
        tasks in 2_usize..24,
        batch in 1_usize..4,
        entry_count in prop::sample::select(vec![8_u32, 16, 64, 1024]),
    ) {
        concurrent_allocations(tasks, batch, entry_count);
    }
}
