// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling"))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::time::{Duration, Instant};

use postgres_harness::TestDatabase;
use registry_breg::audit_tooling::{
    AuditExportCoverage, AuditOperatorService, AuditPruneBoundary, AuditToolingError,
};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::instance_claim::{InstanceClaimError, InstanceClaimService};
use registry_breg::mutation::install_mutation_schema;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, RegistryLockKey, RegistryStateTestIdentity,
};
use registry_platform_audit::{verify_jsonl_lines_with_hasher, AuditEnvelope, AuditProfile};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

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
            .prune(boundary("2999-01-01T00:00:00Z"), None, false)
            .await
            .err(),
        Some(AuditToolingError::BoundaryInFuture),
        "a boundary the database has not reached is refused"
    );

    let nothing = fixture
        .service()
        .prune(boundary("2020-01-01T00:00:00Z"), None, false)
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
        .prune(retention_boundary, None, true)
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

    let (export_bytes, export) = exported(&fixture.service()).await;
    let pruned = fixture
        .service()
        .prune(retention_boundary, Some(&export), false)
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
    assert_eq!(
        record["exportSha256"],
        hex::encode(Sha256::digest(&export_bytes)),
        "the retention record names the export that holds what went"
    );

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
            .prune(boundary("2025-01-01T00:00:00Z"), None, false)
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
            .prune(boundary("2025-01-01T00:00:00Z"), None, false)
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
            .prune(boundary("2025-01-01T00:00:00Z"), None, false)
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

    let (_, export) = exported(&fixture.service()).await;
    let pruned = fixture
        .service()
        .prune(boundary("2024-03-01T00:00:00Z"), Some(&export), false)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prune_refuses_a_boundary_inside_the_minimum_retention() {
    let fixture = Fixture::create().await;
    fixture.seed(2).await;
    let service = fixture.service();

    for dry_run in [true, false] {
        assert_eq!(
            service.prune(days_ago(30), None, dry_run).await.err(),
            Some(AuditToolingError::BoundaryInsideMinimumRetention { minimum_days: 365 }),
            "a boundary thirty days back is inside the default floor (dry run {dry_run})"
        );
    }
    assert_eq!(
        service.prune(days_ago(364), None, true).await.err(),
        Some(AuditToolingError::BoundaryInsideMinimumRetention { minimum_days: 365 }),
        "the floor is a whole year"
    );
    let outside = service
        .prune(days_ago(366), None, true)
        .await
        .expect("a boundary past the floor is planned");
    assert_eq!(outside.removed_records, 0);
    assert_eq!(fixture.record_count().await, 2);

    let short = fixture.service().with_minimum_retention_days_for_test(7);
    assert_eq!(
        short.prune(days_ago(3), None, true).await.err(),
        Some(AuditToolingError::BoundaryInsideMinimumRetention { minimum_days: 7 }),
        "a configured floor is enforced the same way"
    );
    let month_ago = rfc3339(OffsetDateTime::now_utc() - time::Duration::days(30));
    for envelope in fixture.chain().await {
        fixture
            .set_created_at(&envelope.envelope_id, &month_ago)
            .await;
    }
    let (_, export) = exported(&short).await;
    let pruned = short
        .prune(days_ago(10), Some(&export), false)
        .await
        .expect("records older than a shorter configured floor are pruned");
    assert_eq!(pruned.removed_records, 2);

    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prune_removes_only_records_a_verified_export_holds() {
    let fixture = Fixture::create().await;
    let service = fixture.service();
    fixture.seed(2).await;
    let (_, early) = exported(&service).await;
    fixture.seed(2).await;
    let chain = fixture.chain().await;
    assert_eq!(chain.len(), 4);
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
    let first_boundary = boundary("2024-03-01T00:00:00Z");
    let second_boundary = boundary("2025-01-01T00:00:00Z");

    assert_eq!(
        service.prune(second_boundary, None, false).await.err(),
        Some(AuditToolingError::ExportRequired),
        "removing records without an export is refused"
    );
    let plan = service
        .prune(second_boundary, None, true)
        .await
        .expect("a dry run without an export still reports the plan");
    assert_eq!(plan.removed_records, 4);
    assert_eq!(plan.export_sha256, None);

    for dry_run in [true, false] {
        assert_eq!(
            service
                .prune(second_boundary, Some(&early), dry_run)
                .await
                .err(),
            Some(AuditToolingError::ExportDoesNotCover),
            "an export taken before the newest removed records does not cover them (dry run {dry_run})"
        );
    }

    let (full_bytes, full) = exported(&service).await;
    let without_oldest: Vec<u8> = full_bytes
        .split_inclusive(|byte| *byte == b'\n')
        .skip(1)
        .flatten()
        .copied()
        .collect();
    let suffix = service
        .verify_export(&mut without_oldest.as_slice())
        .expect("a suffix of the chain still verifies");
    assert_eq!(suffix.records(), 3);
    assert_eq!(
        service
            .prune(second_boundary, Some(&suffix), false)
            .await
            .err(),
        Some(AuditToolingError::ExportDoesNotCover),
        "an export missing the oldest record does not cover it"
    );
    let empty = service
        .verify_export(&mut b"".as_slice())
        .expect("an empty export verifies and holds nothing");
    assert_eq!(
        service
            .prune(second_boundary, Some(&empty), false)
            .await
            .err(),
        Some(AuditToolingError::ExportDoesNotCover)
    );
    assert_eq!(
        fixture.record_count().await,
        4,
        "no refusal removed a record"
    );

    let digest = hex::encode(Sha256::digest(&full_bytes));
    assert_eq!(full.sha256(), digest);
    let first = service
        .prune(first_boundary, Some(&full), false)
        .await
        .expect("the full export covers the first prefix");
    assert_eq!(first.removed_records, 2);
    assert_eq!(first.export_sha256, Some(digest.clone()));
    let second = service
        .prune(second_boundary, Some(&full), false)
        .await
        .expect(
            "the export still covers what the first prune left, though its oldest records are gone",
        );
    assert_eq!(second.removed_records, 2);

    let retained = fixture.chain().await;
    assert_eq!(retained.len(), 2, "the two retention records remain");
    for record in &retained {
        assert_eq!(record.record["schema"], "breg-audit-retention-audit/v1");
        assert_eq!(record.record["exportSha256"], digest);
    }
    fixture
        .service()
        .verify()
        .await
        .expect("the retained journal still verifies");

    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_export_that_does_not_verify_under_the_deployment_key_is_refused() {
    let fixture = Fixture::create().await;
    fixture.seed(3).await;
    let service = fixture.service();
    let (bytes, _) = exported(&service).await;
    let lines: Vec<&[u8]> = bytes.split_inclusive(|byte| *byte == b'\n').collect();
    assert_eq!(lines.len(), 3);

    let mut tampered: Value = serde_json::from_slice(lines[1]).expect("the line is JSON");
    tampered["record"]["operationId"] = Value::String("records.membership.list".to_owned());
    let mut rewritten = lines[0].to_vec();
    rewritten.extend(serde_json::to_vec(&tampered).expect("the tampered envelope serializes"));
    rewritten.push(b'\n');
    rewritten.extend_from_slice(lines[2]);
    assert_eq!(
        service.verify_export(&mut rewritten.as_slice()).err(),
        Some(AuditToolingError::ExportInvalid { position: 2 }),
        "a rewritten record is refused where it was rewritten"
    );

    let mut reordered = lines[1].to_vec();
    reordered.extend_from_slice(lines[0]);
    assert_eq!(
        service.verify_export(&mut reordered.as_slice()).err(),
        Some(AuditToolingError::ExportInvalid { position: 2 }),
        "records out of chain order are refused"
    );

    assert_eq!(
        service.verify_export(&mut b"not json\n".as_slice()).err(),
        Some(AuditToolingError::ExportInvalid { position: 1 })
    );

    let other_key = fixture.service_with_profile(
        AuditProfile::production_from_secret_bytes(vec![0x5a; 32].into())
            .expect("another keyed audit profile"),
    );
    assert_eq!(
        other_key.verify_export(&mut bytes.as_slice()).err(),
        Some(AuditToolingError::ExportInvalid { position: 1 }),
        "an export from another deployment key does not verify here"
    );

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
                service.prune(boundary("2025-01-01T00:00:00Z"), None, false),
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

/// Measurement rather than a gate: one verification pass over journals of
/// growing size, reported so the walk's cost per record is visible. A walk
/// whose cost per record is flat is linear in the chain length; a walk that
/// carries per-record state proportional to what it has already visited shows
/// the cost per record growing with the journal. Run it with
/// `--ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "seeds journals of up to ten thousand records to measure the walk"]
async fn verify_cost_per_record_over_growing_journals() {
    for records in [1_000usize, 5_000, 10_000] {
        let fixture = Fixture::create().await;
        fixture.seed(records).await;
        let service = fixture.service();
        let started = Instant::now();
        let verified = service.verify().await.expect("the seeded journal verifies");
        let elapsed = started.elapsed();
        assert_eq!(verified.records, records as u64);
        assert_eq!(verified.last_hash, verified.head_hash);
        println!(
            "records={records} verify={:.3}s per_record={:.1}us",
            elapsed.as_secs_f64(),
            elapsed.as_secs_f64() * 1_000_000.0 / records as f64,
        );
        fixture.cleanup().await;
    }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adopting_a_copy_refuses_an_audit_chain_that_does_not_verify() {
    let fixture = Fixture::create().await;
    fixture.seed(3).await;
    let chain = fixture.chain().await;
    fixture.simulate_restored_copy().await;
    let claims = fixture.claims();

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
        claims.adopt().await.err(),
        Some(InstanceClaimError::AuditChain(
            AuditToolingError::ChainBroken { position: 2 }
        )),
        "a copy whose journal does not verify is never adopted"
    );
    let refused = claims.status().await.expect("the claim reads");
    assert!(
        !refused.matches,
        "a refused adoption leaves the claim as it was"
    );
    assert_eq!(refused.claim.map(|claim| claim.epoch), Some(1));

    fixture
        .set_envelope_bytes(&chain[1].envelope_id, &original)
        .await;
    let adoption = claims.adopt().await.expect("a verified copy is adopted");
    assert_eq!(adoption.previous.map(|claim| claim.epoch), Some(1));
    assert_eq!(adoption.current.epoch, 2);
    let verified = fixture
        .service()
        .verify()
        .await
        .expect("the adoption extends a verified chain");
    assert_eq!(verified.records, 4, "the adoption appends one audit record");

    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_claim_is_reported_and_adopting_records_a_fresh_one() {
    let fixture = Fixture::create().await;
    fixture
        .migration
        .execute("DELETE FROM registry_internal.registry_instance_claim", &[])
        .await
        .expect("the owning role can remove the claim");
    let claims = fixture.claims();

    let missing = claims
        .status()
        .await
        .expect("a missing claim still reports");
    assert_eq!(missing.claim, None);
    assert!(!missing.matches, "no claim names this database");

    let adoption = claims
        .adopt()
        .await
        .expect("the operator claims the database");
    assert_eq!(adoption.previous, None);
    assert_eq!(adoption.current.epoch, 1);
    assert_eq!(adoption.current.identity, missing.live);
    assert!(claims.status().await.expect("the claim reads").matches);

    fixture.cleanup().await;
}

/// A database whose audit journal already holds records is either a Registry
/// installed before the claim existed or a copy restored from a backup taken
/// before it. Installing the claim there records none, so the database waits
/// for an operator to adopt it instead of claiming itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn installing_the_claim_beside_audit_records_leaves_the_database_to_adopt() {
    let fixture = Fixture::create().await;
    fixture.seed(2).await;
    fixture
        .migration
        .batch_execute("DROP TABLE registry_internal.registry_instance_claim")
        .await
        .expect("the owning role can drop the claim table");
    install_mutation_schema(&fixture.migration, &fixture.database.runtime_role)
        .await
        .expect("the mutation schema installs again");
    let claims = fixture.claims();

    let unclaimed = claims.status().await.expect("the claim table reads");
    assert_eq!(unclaimed.claim, None, "no claim is recorded beside history");
    assert!(!unclaimed.matches);

    let adoption = claims
        .adopt()
        .await
        .expect("the operator claims the database");
    assert_eq!(adoption.previous, None);
    assert_eq!(adoption.current.epoch, 1);
    install_mutation_schema(&fixture.migration, &fixture.database.runtime_role)
        .await
        .expect("the mutation schema installs again");
    assert_eq!(
        claims
            .status()
            .await
            .expect("the claim reads")
            .claim
            .map(|claim| claim.epoch),
        Some(1),
        "a later install leaves the adopted claim in place"
    );

    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_runtime_role_cannot_rewrite_or_remove_the_instance_claim() {
    let fixture = Fixture::create().await;
    let (runtime, runtime_task) = fixture.database.connect_admin().await;
    runtime
        .batch_execute(&format!(
            "SET ROLE \"{}\"",
            fixture.database.runtime_role.as_str()
        ))
        .await
        .expect("the session takes the runtime role");
    let claimed: i64 = runtime
        .query_one(
            "SELECT epoch FROM registry_internal.registry_instance_claim WHERE singleton",
            &[],
        )
        .await
        .expect("the runtime role reads the claim")
        .get(0);
    assert_eq!(claimed, 1);
    for statement in [
        "UPDATE registry_internal.registry_instance_claim
            SET database_oid = (SELECT oid FROM pg_database WHERE datname = current_database())",
        "UPDATE registry_internal.registry_instance_claim SET epoch = epoch + 1",
        "DELETE FROM registry_internal.registry_instance_claim",
        "INSERT INTO registry_internal.registry_instance_claim
             (singleton, system_identifier, database_oid)
         VALUES (true, 1, 1)",
    ] {
        assert!(
            runtime.execute(statement, &[]).await.is_err(),
            "the runtime role cannot move its own claim: {statement}"
        );
    }
    drop(runtime);
    runtime_task.abort();

    fixture.cleanup().await;
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

fn days_ago(days: i64) -> AuditPruneBoundary {
    boundary(&rfc3339(
        OffsetDateTime::now_utc() - time::Duration::days(days),
    ))
}

fn rfc3339(instant: OffsetDateTime) -> String {
    instant.format(&Rfc3339).expect("the instant formats")
}

/// Export the journal the way `bregctl audit export` does and read the file
/// back the way `bregctl audit prune --export` does.
async fn exported(service: &AuditOperatorService) -> (Vec<u8>, AuditExportCoverage) {
    let mut written = Vec::new();
    service
        .export(&mut written)
        .await
        .expect("the journal exports");
    let coverage = service
        .verify_export(&mut written.as_slice())
        .expect("a fresh export verifies");
    (written, coverage)
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
        self.service_with_profile(self.audit_profile.clone())
    }

    fn service_with_profile(&self, audit_profile: AuditProfile) -> AuditOperatorService {
        AuditOperatorService::new_for_test(
            self.identity.clone(),
            ExpectedManagedCatalog::compiled(&self.registry),
            RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives"),
            self.database.migration_config.clone(),
            self.database.runtime_config.clone(),
            self.database.migration_role.clone(),
            self.database.runtime_role.clone(),
            audit_profile,
        )
    }

    /// Append `count` records over the runtime connection, so the journal under
    /// test is the chain the runtime role writes.
    async fn seed(&self, count: usize) {
        let service = self.service();
        let records = (0..count)
            .map(|sequence| {
                json!({
                    "schema": "breg-audit/v1",
                    "phase": "attempt",
                    "method": "GET",
                    "operationId": "records.membership.get",
                    "sequence": sequence,
                    "packageRevision": PACKAGE_REVISION,
                    "selectedAccessProfile": "writer",
                    "purposePresent": true,
                })
            })
            .collect();
        service
            .append_records_for_test(records)
            .await
            .expect("the runtime role appends every seeded audit record");
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

    fn claims(&self) -> InstanceClaimService {
        InstanceClaimService::new(self.service())
    }

    /// A logical restore keeps every row, so a copy holds the claim its
    /// original recorded while the database it lands in has another oid.
    async fn simulate_restored_copy(&self) {
        self.migration
            .execute(
                "UPDATE registry_internal.registry_instance_claim
                    SET database_oid = 1
                  WHERE singleton",
                &[],
            )
            .await
            .expect("the owning role can rewrite the claim");
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
            "permissions":[{
              "entity":"membership",
              "operations":["create","get","list","patch"],
              "readableFields":["person","household"],
              "writableFields":["person","household"],
              "rowBoundaries": []
            }]
          }]
        }"#,
    )
    .expect("fixture project parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}
