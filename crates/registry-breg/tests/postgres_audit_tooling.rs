// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling"))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::time::Duration;

use postgres_harness::TestDatabase;
use registry_breg::audit_tooling::{AuditOperatorService, AuditPruneBoundary, AuditToolingError};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, RegistryLockKey, RegistryStateTestIdentity,
};
use registry_platform_audit::{verify_jsonl_lines_with_hasher, AuditEnvelope, AuditProfile};
use serde_json::{json, Value};

const PACKAGE_ID: &str = "audit-tooling";
const PACKAGE_REVISION: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const UNKNOWN_HASH: [u8; 32] = [0u8; 32];
/// The operator paths run under a 30-second statement timeout, so a result
/// inside this bound proves the traversal reached a classification instead of
/// leaving the database to fail the statement.
const OPERATOR_BOUND: Duration = Duration::from_secs(10);
/// Records the walk fetches per round trip, which is what makes a journal
/// larger than memory verifiable. Seeding past it puts records in a second
/// batch.
const CHAIN_FETCH_BATCH: usize = 1000;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_reports_the_head_of_an_empty_and_of_a_seeded_journal() {
    let fixture = Fixture::create().await;

    let empty = fixture
        .service()
        .verify()
        .await
        .expect("an empty journal verifies");
    assert_eq!(empty.records, 0);
    assert_eq!(empty.start_prev_hash, None);
    assert_eq!(empty.last_hash, None);
    assert_eq!(empty.head_hash, None);

    fixture.seed(3).await;
    let chain = fixture.chain().await;
    assert_eq!(chain.len(), 3);

    let verified = fixture
        .service()
        .verify()
        .await
        .expect("a seeded journal verifies");
    assert_eq!(verified.records, 3);
    assert_eq!(
        verified.start_prev_hash, None,
        "a journal that was never pruned starts at its genesis record"
    );
    assert_eq!(verified.last_hash, Some(hex::encode(chain[2].record_hash)));
    assert_eq!(verified.head_hash, verified.last_hash);

    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_refuses_a_tampered_envelope_a_rewritten_head_and_a_deleted_record() {
    let fixture = Fixture::create().await;
    fixture.seed(3).await;
    let chain = fixture.chain().await;
    let head = hex::encode(chain[2].record_hash);

    let original = fixture.envelope_bytes(&chain[1].envelope_id).await;
    let mut tampered: Value = serde_json::from_slice(&original).expect("the envelope is JSON");
    tampered["record"]["operationId"] = Value::String("records.membership.list".to_owned());
    fixture
        .set_envelope_bytes(
            &chain[1].envelope_id,
            &serde_json::to_vec(&tampered).expect("the tampered envelope serializes"),
        )
        .await;
    assert_eq!(
        fixture.service().verify().await.err(),
        Some(AuditToolingError::ChainBroken { position: 2 }),
        "a rewritten record body breaks the chain where it was rewritten"
    );
    fixture
        .set_envelope_bytes(&chain[1].envelope_id, &original)
        .await;

    fixture.set_head(Some(UNKNOWN_HASH.as_slice())).await;
    assert_eq!(
        fixture.service().verify().await.err(),
        Some(AuditToolingError::HeadMismatch),
        "a head naming no record leaves the newest record unreachable"
    );
    fixture
        .set_head(Some(chain[2].record_hash.as_slice()))
        .await;
    assert_eq!(
        fixture
            .service()
            .verify()
            .await
            .expect("the restored journal verifies")
            .head_hash,
        Some(head)
    );

    fixture.delete_record(&chain[1].envelope_id).await;
    assert_eq!(
        fixture.service().verify().await.err(),
        Some(AuditToolingError::Unreachable { records: 1 }),
        "a deleted middle record keeps the head reachable and strands the records before it"
    );

    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_reports_a_cyclic_chain_without_waiting_for_the_statement_timeout() {
    let fixture = Fixture::create().await;
    fixture.seed(1).await;
    let chain = fixture.chain().await;
    let original = fixture.envelope_bytes(&chain[0].envelope_id).await;
    let mut cyclic: Value = serde_json::from_slice(&original).expect("the envelope is JSON");
    cyclic["prev_hash"] = Value::String(hex::encode(chain[0].record_hash));
    fixture
        .set_envelope_bytes(
            &chain[0].envelope_id,
            &serde_json::to_vec(&cyclic).expect("the cyclic envelope serializes"),
        )
        .await;

    let result = tokio::time::timeout(Duration::from_secs(5), fixture.service().verify())
        .await
        .expect("cycle detection finishes before the database statement timeout");
    assert_eq!(
        result.err(),
        Some(AuditToolingError::ChainBroken { position: 1 })
    );

    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn export_writes_the_verified_journal_as_json_lines_in_chain_order() {
    let fixture = Fixture::create().await;
    fixture.seed(3).await;
    let chain = fixture.chain().await;

    let mut written = Vec::new();
    let exported = fixture
        .service()
        .export(&mut written)
        .await
        .expect("a verified journal exports");
    assert_eq!(exported.records, 3);
    assert_eq!(exported.last_hash, Some(hex::encode(chain[2].record_hash)));

    let lines = String::from_utf8(written).expect("the export is UTF-8");
    let exported_ids: Vec<String> = lines
        .lines()
        .map(|line| {
            serde_json::from_str::<AuditEnvelope>(line)
                .expect("each line holds one envelope")
                .envelope_id
        })
        .collect();
    let chain_ids: Vec<String> = chain
        .iter()
        .map(|envelope| envelope.envelope_id.clone())
        .collect();
    assert_eq!(
        exported_ids, chain_ids,
        "the export is written oldest first in chain order"
    );

    let round_trip =
        verify_jsonl_lines_with_hasher(lines.lines(), &fixture.audit_profile.chain_hasher())
            .expect("the export verifies off host under the deployment audit key");
    assert_eq!(round_trip.records, 3);
    assert_eq!(round_trip.start_prev_hash, None);
    assert_eq!(round_trip.last_hash, Some(chain[2].record_hash));

    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prune_removes_the_qualifying_prefix_and_records_what_went() {
    let fixture = Fixture::create().await;
    fixture.seed(4).await;
    let chain = fixture.chain().await;
    for (index, envelope) in chain.iter().enumerate() {
        let created_at = if index < 2 {
            "2024-01-01T00:00:00Z"
        } else {
            "2024-06-01T00:00:00Z"
        };
        fixture
            .set_created_at(&envelope.envelope_id, created_at)
            .await;
    }
    let retention_boundary = boundary("2024-03-01T00:00:00Z");

    assert_eq!(
        fixture
            .service()
            .prune(boundary("2999-01-01T00:00:00Z"), false)
            .await
            .err(),
        Some(AuditToolingError::BoundaryInFuture),
        "a boundary the database has not reached is refused"
    );

    let nothing = fixture
        .service()
        .prune(boundary("2020-01-01T00:00:00Z"), false)
        .await
        .expect("a boundary older than every record succeeds");
    assert_eq!(nothing.removed_records, 0);
    assert_eq!(nothing.retained_records, 4);
    assert_eq!(nothing.boundary_hash, None);
    assert_eq!(
        nothing.first_retained_envelope_id,
        Some(chain[0].envelope_id.clone())
    );
    assert_eq!(
        fixture.record_count().await,
        4,
        "a prune that removes nothing appends no retention record"
    );

    let dry_run = fixture
        .service()
        .prune(retention_boundary, true)
        .await
        .expect("a dry run reports the plan");
    assert!(dry_run.dry_run);
    assert_eq!(dry_run.removed_records, 2);
    assert_eq!(dry_run.retained_records, 2);
    assert_eq!(
        dry_run.boundary_hash,
        Some(hex::encode(chain[1].record_hash))
    );
    assert_eq!(
        dry_run.first_retained_envelope_id,
        Some(chain[2].envelope_id.clone())
    );
    assert_eq!(
        fixture.record_count().await,
        4,
        "a dry run leaves every record in place"
    );

    let pruned = fixture
        .service()
        .prune(retention_boundary, false)
        .await
        .expect("the qualifying prefix is removed");
    assert!(!pruned.dry_run);
    assert_eq!(pruned.removed_records, 2);
    assert_eq!(pruned.retained_records, 2);
    assert_eq!(pruned.boundary_hash, dry_run.boundary_hash);
    assert_eq!(
        pruned.first_retained_envelope_id,
        Some(chain[2].envelope_id.clone())
    );
    assert_eq!(
        fixture.record_count().await,
        3,
        "two records go and the retention record arrives"
    );

    let retained = fixture.chain().await;
    let record = &retained[2].record;
    assert_eq!(
        record["schema"], "breg-audit-retention-audit/v1",
        "the retention record is the newest record in the chain"
    );
    assert_eq!(record["phase"], "terminal");
    assert_eq!(record["outcome"], "committed");
    assert_eq!(record["operationId"], "audit.retention.prune");
    assert_eq!(record["packageRevision"], PACKAGE_REVISION);
    assert_eq!(record["removedRecords"], 2);
    assert_eq!(record["retainedRecords"], 2);
    assert_eq!(record["boundaryHash"], hex::encode(chain[1].record_hash));
    assert_eq!(record["before"], "2024-03-01T00:00:00Z");

    let verified = fixture
        .service()
        .verify()
        .await
        .expect("the retained journal still verifies");
    assert_eq!(verified.records, 3);
    assert_eq!(
        verified.start_prev_hash, pruned.boundary_hash,
        "the retained set starts at the boundary the prune reported"
    );
    assert_eq!(verified.last_hash, verified.head_hash);

    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prune_refuses_an_unverified_journal_before_deleting_records() {
    let fixture = Fixture::create().await;
    fixture.seed(3).await;
    let chain = fixture.chain().await;
    let original = fixture.envelope_bytes(&chain[1].envelope_id).await;
    let mut tampered: Value = serde_json::from_slice(&original).expect("the envelope is JSON");
    tampered["record"]["operationId"] = Value::String("records.membership.list".to_owned());
    fixture
        .set_envelope_bytes(
            &chain[1].envelope_id,
            &serde_json::to_vec(&tampered).expect("the tampered envelope serializes"),
        )
        .await;
    assert_eq!(
        fixture
            .service()
            .prune(boundary("2025-01-01T00:00:00Z"), false)
            .await
            .err(),
        Some(AuditToolingError::ChainBroken { position: 2 })
    );
    assert_eq!(fixture.record_count().await, 3);
    fixture.cleanup().await;

    let fixture = Fixture::create().await;
    fixture.seed(3).await;
    fixture.set_head(Some(UNKNOWN_HASH.as_slice())).await;
    assert_eq!(
        fixture
            .service()
            .prune(boundary("2025-01-01T00:00:00Z"), false)
            .await
            .err(),
        Some(AuditToolingError::HeadMismatch)
    );
    assert_eq!(fixture.record_count().await, 3);
    fixture.cleanup().await;

    let fixture = Fixture::create().await;
    fixture.seed(3).await;
    let chain = fixture.chain().await;
    fixture.delete_record(&chain[1].envelope_id).await;
    assert_eq!(
        fixture
            .service()
            .prune(boundary("2025-01-01T00:00:00Z"), false)
            .await
            .err(),
        Some(AuditToolingError::Unreachable { records: 1 })
    );
    assert_eq!(fixture.record_count().await, 2);
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prune_stops_at_the_first_record_the_boundary_retains() {
    let fixture = Fixture::create().await;
    fixture.seed(4).await;
    let chain = fixture.chain().await;
    // The third record straddles the boundary: the record after it is older by
    // timestamp, so timestamp order and chain order disagree and only chain
    // order may decide what a prune removes.
    for (index, envelope) in chain.iter().enumerate() {
        let created_at = if index == 2 {
            "2024-06-01T00:00:00Z"
        } else {
            "2024-01-01T00:00:00Z"
        };
        fixture
            .set_created_at(&envelope.envelope_id, created_at)
            .await;
    }

    let pruned = fixture
        .service()
        .prune(boundary("2024-03-01T00:00:00Z"), false)
        .await
        .expect("the prefix before the straddling record is removed");
    assert_eq!(
        pruned.removed_records, 2,
        "the walk stops at the first record the boundary retains, not at the last old record"
    );
    assert_eq!(pruned.retained_records, 2);
    assert_eq!(
        pruned.first_retained_envelope_id,
        Some(chain[2].envelope_id.clone())
    );
    assert_eq!(fixture.record_count().await, 3);

    let verified = fixture
        .service()
        .verify()
        .await
        .expect("the retained journal still verifies");
    assert_eq!(verified.records, 3);
    assert_eq!(verified.start_prev_hash, pruned.boundary_hash);

    fixture.cleanup().await;
}

/// A stored envelope the chain traversal cannot turn into a link is an
/// integrity failure of the journal, not an unavailable database. Every shape
/// below rewrites one record into bytes the recursive expression has to carry
/// without raising, so the walk reaches the record and reports it as an
/// unreadable envelope.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_export_and_prune_report_malformed_links_as_unreadable_envelopes() {
    let fixture = Fixture::create().await;
    fixture.seed(3).await;
    let chain = fixture.chain().await;
    let original = fixture.envelope_bytes(&chain[1].envelope_id).await;

    for malformed in malformed_envelopes(&original) {
        let shape = malformed.shape;
        fixture
            .set_envelope_bytes(&chain[1].envelope_id, &malformed.bytes)
            .await;
        let expected = Some(AuditToolingError::InvalidEnvelope {
            position: malformed.position,
        });
        let service = fixture.service();

        assert_eq!(
            bounded(service.verify(), shape).await.err(),
            expected,
            "verify reports {shape} as an unreadable envelope"
        );

        let mut written = Vec::new();
        assert_eq!(
            bounded(service.export(&mut written), shape).await.err(),
            expected,
            "export reports {shape} as an unreadable envelope"
        );

        assert_eq!(
            bounded(
                service.prune(boundary("2025-01-01T00:00:00Z"), false),
                shape
            )
            .await
            .err(),
            expected,
            "prune reports {shape} as an unreadable envelope"
        );
        assert_eq!(
            fixture.record_count().await,
            3,
            "prune removed no record after refusing {shape}"
        );

        fixture
            .set_envelope_bytes(&chain[1].envelope_id, &original)
            .await;
        assert_eq!(
            fixture
                .service()
                .verify()
                .await
                .expect("the restored journal verifies")
                .records,
            3,
            "the journal verifies again once {shape} is restored"
        );
    }

    fixture.cleanup().await;
}

/// A record body may hold text outside ASCII, so the traversal has to carry the
/// bytes that text is stored as and still recover the link from them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_and_export_carry_records_holding_text_outside_ascii() {
    let fixture = Fixture::create().await;
    let notes = ["Ångström", "東京都", "Ćwikła", "🔒"];
    let service = fixture.service();
    for note in notes {
        service
            .append_record_for_test(json!({
                "schema": "breg-audit/v1",
                "phase": "attempt",
                "method": "GET",
                "operationId": "records.membership.get",
                "packageRevision": PACKAGE_REVISION,
                "note": note,
            }))
            .await
            .expect("the runtime role appends one audit record");
    }
    let chain = fixture.chain().await;
    let stored = fixture.envelope_bytes(&chain[0].envelope_id).await;
    assert!(
        stored.iter().any(|byte| *byte >= 0x80),
        "the stored envelope holds the bytes the text is written as"
    );

    let mut written = Vec::new();
    let exported = service
        .export(&mut written)
        .await
        .expect("a journal of records holding text outside ASCII verifies and exports");
    assert_eq!(exported.records, 4);
    assert_eq!(
        exported.last_hash,
        Some(hex::encode(chain[3].record_hash)),
        "every link is recovered, so the walk ends at the newest record"
    );

    let lines = String::from_utf8(written).expect("the export is UTF-8");
    let exported_notes: Vec<String> = lines
        .lines()
        .map(|line| {
            serde_json::from_str::<AuditEnvelope>(line)
                .expect("each line holds one envelope")
                .record["note"]
                .as_str()
                .expect("each record keeps its note")
                .to_owned()
        })
        .collect();
    assert_eq!(exported_notes, notes);

    fixture.cleanup().await;
}

/// The walk fetches the chain in batches so a journal larger than memory still
/// verifies. A malformed record in a later batch has to be reported at its own
/// position, which proves the batches are still linked and counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_streams_past_one_fetch_batch_and_reports_a_malformed_link_in_a_later_batch() {
    let fixture = Fixture::create().await;
    let records = CHAIN_FETCH_BATCH + 2;
    fixture.seed(records).await;
    let chain = fixture.chain().await;
    assert_eq!(chain.len(), records);

    let verified = fixture
        .service()
        .verify()
        .await
        .expect("a journal larger than one fetch batch verifies");
    assert_eq!(verified.records, records as u64);
    assert_eq!(verified.last_hash, verified.head_hash);

    // The first record of the second batch, rewritten into bytes that still
    // name their previous record so the whole chain stays reachable.
    let mut unreadable = fixture
        .envelope_bytes(&chain[CHAIN_FETCH_BATCH].envelope_id)
        .await;
    unreadable.pop();
    fixture
        .set_envelope_bytes(&chain[CHAIN_FETCH_BATCH].envelope_id, &unreadable)
        .await;
    assert_eq!(
        fixture.service().verify().await.err(),
        Some(AuditToolingError::InvalidEnvelope {
            position: CHAIN_FETCH_BATCH as u64 + 1
        }),
        "the record is reported at its chain position, counted from the batch base"
    );

    fixture.cleanup().await;
}

/// Cycle detection is what keeps the traversal bounded when the links form a
/// loop rather than a chain, including a loop that runs through every record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_reports_a_cycle_through_every_record_without_walking_it_twice() {
    let fixture = Fixture::create().await;
    fixture.seed(3).await;
    let chain = fixture.chain().await;
    let original = fixture.envelope_bytes(&chain[0].envelope_id).await;
    let mut cyclic: Value = serde_json::from_slice(&original).expect("the envelope is JSON");
    cyclic["prev_hash"] = Value::String(hex::encode(chain[2].record_hash));
    fixture
        .set_envelope_bytes(
            &chain[0].envelope_id,
            &serde_json::to_vec(&cyclic).expect("the cyclic envelope serializes"),
        )
        .await;

    assert_eq!(
        bounded(fixture.service().verify(), "a cycle through every record")
            .await
            .err(),
        Some(AuditToolingError::ChainBroken { position: 1 })
    );

    fixture.cleanup().await;
}

/// One rewritten envelope and the chain position the walk reports it at.
struct MalformedEnvelope {
    shape: &'static str,
    bytes: Vec<u8>,
    /// Bytes that still name a previous record keep the records before them
    /// reachable, so the walk reaches the rewritten record second. Bytes that
    /// name none stop the recursion, which leaves the rewritten record the
    /// oldest one the walk can reach.
    position: u64,
}

/// The malformed link shapes the traversal has to survive, each built from one
/// stored envelope.
fn malformed_envelopes(original: &[u8]) -> Vec<MalformedEnvelope> {
    let parsed: Value = serde_json::from_slice(original).expect("the envelope is JSON");
    // An envelope holds hex hashes, a Crockford ULID, lower-case keys, and this
    // fixture's ASCII record bodies, so a marker byte written into the record
    // names one position to replace with a byte the traversal has to carry.
    let marked = |byte: u8| {
        let mut envelope = parsed.clone();
        envelope["record"]["marker"] = Value::String("@".to_owned());
        let mut bytes = serde_json::to_vec(&envelope).expect("the marked envelope serializes");
        let markers: Vec<usize> = bytes
            .iter()
            .enumerate()
            .filter(|(_, value)| **value == b'@')
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            markers.len(),
            1,
            "the marked envelope holds one marker byte"
        );
        bytes[markers[0]] = byte;
        bytes
    };
    let with_prev_hash = |prev_hash: Value| {
        let mut envelope = parsed.clone();
        envelope["prev_hash"] = prev_hash;
        serde_json::to_vec(&envelope).expect("the rewritten envelope serializes")
    };
    let unterminated = {
        let mut bytes = original.to_vec();
        bytes.pop();
        bytes
    };
    vec![
        MalformedEnvelope {
            shape: "a byte no UTF-8 decoding accepts",
            bytes: marked(0xff),
            position: 2,
        },
        MalformedEnvelope {
            shape: "a zero byte",
            bytes: marked(0x00),
            position: 2,
        },
        MalformedEnvelope {
            shape: "JSON that ends before it closes",
            bytes: unterminated,
            position: 2,
        },
        MalformedEnvelope {
            shape: "bytes that are not JSON",
            bytes: b"not json".to_vec(),
            position: 1,
        },
        MalformedEnvelope {
            shape: "JSON that is not an object",
            bytes: b"[1,2,3]".to_vec(),
            position: 1,
        },
        MalformedEnvelope {
            shape: "a prev_hash that is not hex",
            bytes: with_prev_hash(Value::String("zz".repeat(32))),
            position: 1,
        },
        MalformedEnvelope {
            shape: "a prev_hash with an odd number of hex digits",
            bytes: with_prev_hash(Value::String("a".repeat(63))),
            position: 1,
        },
        MalformedEnvelope {
            shape: "a prev_hash that is not a JSON string",
            bytes: with_prev_hash(json!(5)),
            position: 1,
        },
    ]
}

async fn bounded<T>(
    operation: impl Future<Output = Result<T, AuditToolingError>>,
    shape: &str,
) -> Result<T, AuditToolingError> {
    tokio::time::timeout(OPERATOR_BOUND, operation)
        .await
        .unwrap_or_else(|_| panic!("the operator path finishes within the bound for {shape}"))
}

fn boundary(value: &str) -> AuditPruneBoundary {
    AuditPruneBoundary::parse_rfc3339(value).expect("the test boundary parses")
}

struct Fixture {
    database: TestDatabase,
    migration: tokio_postgres::Client,
    migration_task: tokio::task::JoinHandle<()>,
    registry: registry_breg::CompiledRegistry,
    identity: ExpectedRegistryIdentity,
    audit_profile: AuditProfile,
}

impl Fixture {
    async fn create() -> Self {
        let database = TestDatabase::create(4).await;
        let registry = compiled_registry();
        let (migration, migration_task) = database.connect_migration().await;
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("compiled schema installs");
        let identity = initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: PACKAGE_ID,
                environment: "local",
                instance_id: "audit-tooling-instance",
                database_id: "audit-tooling-database",
                package_revision: PACKAGE_REVISION,
                package_sequence: 1,
            },
        )
        .await
        .expect("active package identity initializes");
        let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x8b; 32].into())
            .expect("test audit profile is keyed");
        Self {
            database,
            migration,
            migration_task,
            registry,
            identity,
            audit_profile,
        }
    }

    fn service(&self) -> AuditOperatorService {
        AuditOperatorService::new_for_test(
            self.identity.clone(),
            ExpectedManagedCatalog::compiled(&self.registry),
            RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives"),
            self.database.migration_config.clone(),
            self.database.runtime_config.clone(),
            self.database.migration_role.clone(),
            self.database.runtime_role.clone(),
            self.audit_profile.clone(),
        )
    }

    /// Append `count` records over the runtime connection, so the journal under
    /// test is the chain the runtime role writes.
    async fn seed(&self, count: usize) {
        let service = self.service();
        for sequence in 0..count {
            service
                .append_record_for_test(json!({
                    "schema": "breg-audit/v1",
                    "phase": "attempt",
                    "method": "GET",
                    "operationId": "records.membership.get",
                    "sequence": sequence,
                    "packageRevision": PACKAGE_REVISION,
                    "selectedAccessProfile": "writer",
                    "purposePresent": true,
                }))
                .await
                .expect("the runtime role appends one audit record");
        }
    }

    /// Recover chain order in the test the way an operator has to read it: from
    /// the links, never from `created_at`.
    async fn chain(&self) -> Vec<AuditEnvelope> {
        let rows = self
            .migration
            .query("SELECT envelope FROM registry_internal.registry_audit", &[])
            .await
            .expect("the journal is readable");
        let mut by_previous: HashMap<Option<String>, AuditEnvelope> = HashMap::new();
        let mut hashes: HashSet<String> = HashSet::new();
        for row in rows {
            let bytes: Vec<u8> = row.get(0);
            let envelope: AuditEnvelope =
                serde_json::from_slice(&bytes).expect("each stored envelope parses");
            hashes.insert(hex::encode(envelope.record_hash));
            by_previous.insert(envelope.prev_hash.map(hex::encode), envelope);
        }
        // The retained set starts at the record whose predecessor is absent,
        // which is the genesis record until a prune moves the boundary.
        let mut previous = by_previous
            .keys()
            .find(|key| key.as_ref().is_none_or(|hash| !hashes.contains(hash)))
            .cloned()
            .unwrap_or_default();
        let mut ordered = Vec::new();
        while let Some(envelope) = by_previous.remove(&previous) {
            previous = Some(hex::encode(envelope.record_hash));
            ordered.push(envelope);
        }
        ordered
    }

    async fn record_count(&self) -> i64 {
        self.migration
            .query_one("SELECT count(*) FROM registry_internal.registry_audit", &[])
            .await
            .expect("the journal is countable")
            .get(0)
    }

    async fn envelope_bytes(&self, envelope_id: &str) -> Vec<u8> {
        self.migration
            .query_one(
                "SELECT envelope FROM registry_internal.registry_audit WHERE envelope_id = $1",
                &[&envelope_id],
            )
            .await
            .expect("the envelope is readable")
            .get(0)
    }

    async fn set_envelope_bytes(&self, envelope_id: &str, envelope: &[u8]) {
        self.migration
            .execute(
                "UPDATE registry_internal.registry_audit
                    SET envelope = $2
                  WHERE envelope_id = $1",
                &[&envelope_id, &envelope],
            )
            .await
            .expect("the owning role can rewrite one envelope");
    }

    async fn set_created_at(&self, envelope_id: &str, created_at: &str) {
        self.migration
            .execute(
                "UPDATE registry_internal.registry_audit
                    SET created_at = $2::text::timestamptz
                  WHERE envelope_id = $1",
                &[&envelope_id, &created_at],
            )
            .await
            .expect("the owning role can set one created timestamp");
    }

    async fn set_head(&self, last_hash: Option<&[u8]>) {
        self.migration
            .execute(
                "UPDATE registry_internal.registry_audit_head
                    SET last_hash = $1
                  WHERE singleton",
                &[&last_hash],
            )
            .await
            .expect("the owning role can rewrite the audit head");
    }

    async fn delete_record(&self, envelope_id: &str) {
        self.migration
            .execute(
                "DELETE FROM registry_internal.registry_audit WHERE envelope_id = $1",
                &[&envelope_id],
            )
            .await
            .expect("the owning role can delete one record");
    }

    async fn cleanup(self) {
        drop(self.migration);
        self.migration_task.abort();
        self.database.cleanup().await;
    }
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"audit-tooling-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"membership",
            "primaryDataset":"test-dataset",
            "route":"memberships",
            "mutationMode":"mutable",
            "tombstone":true,
            "classification":"restricted",
            "fields":[
              {"id":"person","type":"uuid","required":true,"classification":"internal"},
              {"id":"household","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"writer",
            "default":true,
            "principalClaim":"registry_principal",
            "requiredPurposes":["operations"],
            "grants":[{
              "entity":"membership",
              "operations":["create","get","list","patch"],
              "readableFields":["person","household"],
              "writableFields":["person","household"]
            }]
          }]
        }"#,
    )
    .expect("fixture project parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}
