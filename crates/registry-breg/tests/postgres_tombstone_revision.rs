// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::BTreeSet;
use std::time::Duration;

use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::{parse_project_json, Operation};
use registry_breg::idempotency::PermittedResponseHeader;
use registry_breg::mutation::{
    MutationBody, MutationCoordinator, MutationError, MutationFaultPoint, MutationOutcome,
    MutationPlan, MutationRequest, PatchOperation,
};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema, ClaimContext,
    ExpectedRegistryIdentity, RegistryLockKey, RegistryStateTestIdentity, RowBoundaryContext,
};
use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Map, Value};

const PRINCIPAL_CANARY: &str = "tombstone-principal-canary";
const IDEMPOTENCY_CANARY: &str = "tombstone-idempotency-canary";
const PACKAGE_ID: &str = "tombstone-registry";
const INSTANCE_ID: &str = "tombstone-instance";
const DATABASE_ID: &str = "tombstone-database";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tombstone_revisions_survive_package_upgrade_and_replay_exactly() {
    let fixture = Fixture::start(41, "package-tombstone-1", 1).await;
    let mut client = fixture
        .database
        .runtime_config
        .build_pool()
        .expect("pool builds")
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let create_plan = MutationPlan::from_compiled(&fixture.compiled, "records.widget.create")
        .expect("create route is compiled");
    let patch_plan = MutationPlan::from_compiled(&fixture.compiled, "records.widget.patch")
        .expect("patch route is compiled");
    let tombstone_plan = MutationPlan::from_compiled(&fixture.compiled, "records.widget.tombstone")
        .expect("tombstone route is compiled");
    let claims = mutation_claims(&fixture.compiled, PRINCIPAL_CANARY);
    let response_fields = response_fields();

    let created = fixture
        .coordinator
        .execute(
            &mut client,
            create_request(&create_plan, "create-key", &claims, "original-label"),
        )
        .await
        .expect("create commits");
    let record_id = response_id(&created);
    let mut upgraded_identity = fixture.identity.clone();
    upgraded_identity.package_revision = "package-tombstone-2".to_owned();
    upgraded_identity.package_sequence = 2;
    fixture
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
             SET active_package_revision = $1, package_sequence = $2
             WHERE singleton",
            &[
                &upgraded_identity.package_revision,
                &upgraded_identity.package_sequence,
            ],
        )
        .await
        .expect("test simulates a same-schema package upgrade");
    let upgraded = MutationCoordinator::new(
        fixture.lock_key,
        Duration::from_secs(2),
        upgraded_identity,
        fixture.profile.clone(),
    );
    let package_two_etag = response_etag(
        &fixture.profile,
        &claims,
        "package-tombstone-2",
        &record_id,
        1,
        &response_fields,
    );
    let patched = upgraded
        .execute(
            &mut client,
            patch_request(
                &patch_plan,
                "patch-key",
                &claims,
                &record_id,
                &package_two_etag,
                "patched-label",
            ),
        )
        .await
        .expect("patch commits under the upgraded package");
    assert_eq!(response_revision(&patched), 2);
    let before_tombstone = durable_counts(&fixture.database, &fixture.table).await;
    let tombstoned = upgraded
        .execute(
            &mut client,
            tombstone_request(
                &tombstone_plan,
                IDEMPOTENCY_CANARY,
                &claims,
                &record_id,
                &response_header(&patched, PermittedResponseHeader::Etag),
            ),
        )
        .await
        .expect("tombstone commits");
    assert!(!tombstoned.replayed());
    assert_eq!(response_revision(&tombstoned), 3);
    assert_one_complete_effect(
        before_tombstone,
        durable_counts(&fixture.database, &fixture.table).await,
        0,
    );
    assert_current_row_tombstoned(&fixture.database, &fixture.table, &record_id).await;
    assert_three_revisions_one_record_across_package_upgrade(&fixture.database, &record_id).await;
    assert_tombstone_event_is_canonical(&fixture.database, &record_id).await;
    let event_id = tombstone_event_id(&fixture.database).await;

    let before_replay = durable_counts(&fixture.database, &fixture.table).await;
    let replay = upgraded
        .execute(
            &mut client,
            tombstone_request(
                &tombstone_plan,
                IDEMPOTENCY_CANARY,
                &claims,
                &record_id,
                &response_header(&patched, PermittedResponseHeader::Etag),
            ),
        )
        .await
        .expect("exact tombstone replay succeeds");
    assert!(replay.replayed());
    assert!(
        replay.response() == tombstoned.response(),
        "exact tombstone replay response changed"
    );
    assert_eq!(tombstone_event_id(&fixture.database).await, event_id);
    assert_audited_replay_only(
        before_replay,
        durable_counts(&fixture.database, &fixture.table).await,
    );
    assert_revision_provenance_is_keyed(&fixture.database).await;
    assert_audit_excludes_raw_values(
        &fixture.database,
        &[&record_id, PRINCIPAL_CANARY, IDEMPOTENCY_CANARY],
    )
    .await;

    fixture.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tombstone_refusals_faults_and_concurrency_have_no_duplicate_effects() {
    let fixture = Fixture::start(42, "package-tombstone-faults-1", 1).await;
    let pool = fixture
        .database
        .runtime_config
        .build_pool()
        .expect("pool builds");
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let create_plan = MutationPlan::from_compiled(&fixture.compiled, "records.widget.create")
        .expect("create route is compiled");
    let tombstone_plan = MutationPlan::from_compiled(&fixture.compiled, "records.widget.tombstone")
        .expect("tombstone route is compiled");
    let claims = mutation_claims(&fixture.compiled, PRINCIPAL_CANARY);

    assert!(matches!(
        MutationPlan::from_compiled(&fixture.compiled, "records.log.tombstone"),
        Err(MutationError::InvalidRequest)
    ));
    let without_tombstone = compiled_registry(false);
    assert!(matches!(
        MutationPlan::from_compiled(&without_tombstone, "records.widget.tombstone"),
        Err(MutationError::InvalidRequest)
    ));

    let stale_seed = fixture
        .coordinator
        .execute(
            &mut client,
            create_request(&create_plan, "stale-seed-key", &claims, "stale-seed"),
        )
        .await
        .expect("seed create commits");
    let stale_id = response_id(&stale_seed);
    let before_stale = durable_counts(&fixture.database, &fixture.table).await;
    let stale = fixture
        .coordinator
        .execute(
            &mut client,
            tombstone_request(
                &tombstone_plan,
                "stale-key",
                &claims,
                &stale_id,
                "\"breg-stale\"",
            ),
        )
        .await;
    assert!(
        matches!(stale, Err(MutationError::PreconditionFailed)),
        "stale tombstone ETag was not refused value-free"
    );
    assert_audited_refusal_only(
        before_stale,
        durable_counts(&fixture.database, &fixture.table).await,
    );

    let changed_context = fixture
        .coordinator
        .execute(
            &mut client,
            tombstone_request(
                &tombstone_plan,
                "changed-context-seed-key",
                &claims,
                &stale_id,
                &response_header(&stale_seed, PermittedResponseHeader::Etag),
            ),
        )
        .await
        .expect("first tombstone commits");
    let other_claims = mutation_claims(&fixture.compiled, "other-principal");
    let before_changed_context = durable_counts(&fixture.database, &fixture.table).await;
    let changed_context_reuse = fixture
        .coordinator
        .execute(
            &mut client,
            tombstone_request(
                &tombstone_plan,
                "changed-context-seed-key",
                &other_claims,
                &stale_id,
                &response_header(&stale_seed, PermittedResponseHeader::Etag),
            ),
        )
        .await;
    assert!(
        matches!(
            changed_context_reuse,
            Err(MutationError::IdempotencyConflict)
        ),
        "changed idempotency context was not refused value-free"
    );
    assert_audited_refusal_only(
        before_changed_context,
        durable_counts(&fixture.database, &fixture.table).await,
    );

    let before_already = durable_counts(&fixture.database, &fixture.table).await;
    let already = fixture
        .coordinator
        .execute(
            &mut client,
            tombstone_request(
                &tombstone_plan,
                "already-key",
                &claims,
                &stale_id,
                &response_header(&changed_context, PermittedResponseHeader::Etag),
            ),
        )
        .await;
    assert!(
        matches!(already, Err(MutationError::PreconditionFailed)),
        "already tombstoned row was not refused value-free"
    );
    assert_audited_refusal_only(
        before_already,
        durable_counts(&fixture.database, &fixture.table).await,
    );

    for (index, fault) in [
        MutationFaultPoint::BeforeCurrentRow,
        MutationFaultPoint::BeforeRevision,
        MutationFaultPoint::BeforeOutbox,
        MutationFaultPoint::BeforeTerminalAudit,
        MutationFaultPoint::BeforeIdempotency,
        MutationFaultPoint::BeforeCommit,
    ]
    .into_iter()
    .enumerate()
    {
        let seed = fixture
            .coordinator
            .execute(
                &mut client,
                create_request(
                    &create_plan,
                    &format!("fault-seed-key-{index}"),
                    &claims,
                    &format!("fault-seed-{index}"),
                ),
            )
            .await
            .expect("fault seed commits");
        let seed_id = response_id(&seed);
        let before = durable_counts(&fixture.database, &fixture.table).await;
        let failed = fixture
            .coordinator
            .execute_with_fault(
                &mut client,
                tombstone_request(
                    &tombstone_plan,
                    &format!("fault-key-{index}"),
                    &claims,
                    &seed_id,
                    &response_header(&seed, PermittedResponseHeader::Etag),
                ),
                fault,
            )
            .await;
        assert!(
            matches!(failed, Err(MutationError::Unavailable)),
            "fault injection did not fail value-free"
        );
        assert_eq!(
            durable_counts(&fixture.database, &fixture.table).await,
            DurableCounts {
                audit: before.audit + 1,
                ..before
            }
        );
        assert_current_row_active(&fixture.database, &fixture.table, &seed_id).await;
    }

    let recovery_seed = fixture
        .coordinator
        .execute(
            &mut client,
            create_request(&create_plan, "recovery-seed-key", &claims, "recovery-seed"),
        )
        .await
        .expect("recovery seed commits");
    let recovery_id = response_id(&recovery_seed);
    let before_recovery = durable_counts(&fixture.database, &fixture.table).await;
    let lost = fixture
        .coordinator
        .execute_with_fault(
            &mut client,
            tombstone_request(
                &tombstone_plan,
                "recovery-key",
                &claims,
                &recovery_id,
                &response_header(&recovery_seed, PermittedResponseHeader::Etag),
            ),
            MutationFaultPoint::AfterCommitBeforeResponseRelease,
        )
        .await;
    assert!(
        matches!(lost, Err(MutationError::Unavailable)),
        "post-commit lost response fault did not fail value-free"
    );
    assert_one_complete_effect(
        before_recovery,
        durable_counts(&fixture.database, &fixture.table).await,
        0,
    );
    let recovery_replay = fixture
        .coordinator
        .execute(
            &mut client,
            tombstone_request(
                &tombstone_plan,
                "recovery-key",
                &claims,
                &recovery_id,
                &response_header(&recovery_seed, PermittedResponseHeader::Etag),
            ),
        )
        .await
        .expect("post-commit lost response replays");
    assert!(recovery_replay.replayed());

    let concurrent_seed = fixture
        .coordinator
        .execute(
            &mut client,
            create_request(
                &create_plan,
                "concurrent-seed-key",
                &claims,
                "concurrent-seed",
            ),
        )
        .await
        .expect("concurrent seed commits");
    let concurrent_id = response_id(&concurrent_seed);
    let concurrent_etag = response_header(&concurrent_seed, PermittedResponseHeader::Etag);
    let before_concurrent = durable_counts(&fixture.database, &fixture.table).await;
    let mut first = pool
        .get_for_test()
        .await
        .expect("first concurrent connection is available");
    let mut second = pool
        .get_for_test()
        .await
        .expect("second concurrent connection is available");
    let (left, right) = tokio::join!(
        fixture.coordinator.execute(
            &mut first,
            tombstone_request(
                &tombstone_plan,
                "concurrent-key-one",
                &claims,
                &concurrent_id,
                &concurrent_etag,
            ),
        ),
        fixture.coordinator.execute(
            &mut second,
            tombstone_request(
                &tombstone_plan,
                "concurrent-key-two",
                &claims,
                &concurrent_id,
                &concurrent_etag,
            ),
        ),
    );
    let successes = [&left, &right]
        .iter()
        .filter(|result| result.is_ok())
        .count();
    let stale = [&left, &right]
        .iter()
        .filter(|result| matches!(result, Err(MutationError::PreconditionFailed)))
        .count();
    assert_eq!(successes, 1);
    assert_eq!(stale, 1);
    assert_eq!(
        durable_counts(&fixture.database, &fixture.table).await,
        DurableCounts {
            revisions: before_concurrent.revisions + 1,
            outbox: before_concurrent.outbox + 1,
            audit: before_concurrent.audit + 4,
            idempotency: before_concurrent.idempotency + 1,
            ..before_concurrent
        }
    );

    fixture.database.cleanup().await;
}

struct Fixture {
    database: TestDatabase,
    compiled: registry_breg::CompiledRegistry,
    identity: ExpectedRegistryIdentity,
    coordinator: MutationCoordinator,
    lock_key: RegistryLockKey,
    profile: AuditProfile,
    table: String,
}

impl Fixture {
    async fn start(pool_size: usize, package_revision: &str, package_sequence: i64) -> Self {
        let database = TestDatabase::create(pool_size).await;
        let (migration, migration_task) = database.connect_migration().await;
        let compiled = compiled_registry(true);
        install_compiled_schema(&migration, &compiled, &database.runtime_role)
            .await
            .expect("migration installs schema");
        let identity = initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &compiled,
            RegistryStateTestIdentity {
                package_id: PACKAGE_ID,
                environment: "local",
                instance_id: INSTANCE_ID,
                database_id: DATABASE_ID,
                package_revision,
                package_sequence,
            },
        )
        .await
        .expect("migration initializes state");
        migration_task.abort();
        let profile = AuditProfile::production_from_secret_bytes(vec![0x63; 32].into())
            .expect("test owns keyed audit profile");
        let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock id is bounded");
        let coordinator = MutationCoordinator::new(
            lock_key,
            Duration::from_secs(2),
            identity.clone(),
            profile.clone(),
        );
        let table = compiled.entities()["widget"].physical_table.clone();
        Self {
            database,
            compiled,
            identity,
            coordinator,
            lock_key,
            profile,
            table,
        }
    }
}

fn compiled_registry(tombstone: bool) -> registry_breg::CompiledRegistry {
    let tombstone_fragment = if tombstone {
        r#","tombstone":true"#
    } else {
        ""
    };
    let operations = if tombstone {
        r#""create","get","list","patch","tombstone""#
    } else {
        r#""create","get","list","patch""#
    };
    let events = if tombstone {
        r#",
            "events":[
              {"id":"widget-created","trigger":"created","projection":["label"]},
              {"id":"widget-patched","trigger":"patched","projection":["label","quantity"]},
              {"id":"widget-tombstoned","trigger":"tombstoned","projection":["label","quantity"]}
            ]"#
    } else {
        r#",
            "events":[
              {"id":"widget-created","trigger":"created","projection":["label"]},
              {"id":"widget-patched","trigger":"patched","projection":["label","quantity"]}
            ]"#
    };
    let project = parse_project_json(
        format!(
            r#"{{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{{"id":"tombstone-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
          "entities":[{{
            "id":"widget","primaryDataset":"test-dataset","route":"widgets","mutationMode":"mutable"{tombstone_fragment},"classification":"public",
            "fields":[
              {{"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"}},
              {{"id":"label","type":"string","maxLength":128,"required":true,"classification":"public"}},
              {{"id":"quantity","type":"int64","required":true,"classification":"public"}}
            ]{events}
          }},{{
            "id":"log","primaryDataset":"test-dataset","route":"logs","mutationMode":"create_only","classification":"public",
            "fields":[
              {{"id":"jurisdiction","type":"string","maxLength":32,"required":true,"classification":"public"}},
              {{"id":"message","type":"string","maxLength":128,"required":true,"classification":"public"}}
            ]
          }}],
          "accessProfiles":[{{
            "id":"operator","default":true,"principalClaim":"registry_principal",
            "requiredPurposes":["case-management"],
            "grants":[{{
              "entity":"widget","operations":[{operations}],
              "readableFields":["jurisdiction","label","quantity"],
              "writableFields":["jurisdiction","label","quantity"],
              "rowBoundaries":[{{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}}]
            }},{{
              "entity":"log","operations":["create","get","list"],
              "readableFields":["jurisdiction","message"],
              "writableFields":["jurisdiction","message"],
              "rowBoundaries":[{{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}}]
            }}]
          }}]
        }}"#
        )
        .as_bytes(),
    )
    .expect("fixture parses");
    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("fixture compiles to trusted inventories");
    assert_eq!(
        compiled.routes().routes.iter().any(|route| {
            route.id == "records.widget.tombstone" && route.operation == Operation::Tombstone
        }),
        tombstone
    );
    compiled
}

fn mutation_claims(registry: &registry_breg::CompiledRegistry, principal: &str) -> ClaimContext {
    ClaimContext::for_compiled(
        registry,
        "widget",
        Some(principal.to_owned()),
        "operator",
        Some("case-management".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "zone-a".to_owned(),
        }],
    )
    .expect("claim context is compiler-bound")
}

fn create_request<'a>(
    plan: &'a MutationPlan,
    key: &'a str,
    claims: &'a ClaimContext,
    label: &str,
) -> MutationRequest<'a> {
    MutationRequest {
        plan,
        idempotency_key: key,
        claims,
        record_id: None,
        expected_etag: None,
        body: MutationBody::Create(Map::from_iter([
            (
                "jurisdiction".to_owned(),
                Value::String("zone-a".to_owned()),
            ),
            ("label".to_owned(), Value::String(label.to_owned())),
            ("quantity".to_owned(), json!(7)),
        ])),
        response_fields: response_fields(),
        representation: registry_breg::record_profile::RecordRepresentation::Json,
        correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
    }
}

fn patch_request<'a>(
    plan: &'a MutationPlan,
    key: &'a str,
    claims: &'a ClaimContext,
    record_id: &'a str,
    expected_etag: &'a str,
    label: &str,
) -> MutationRequest<'a> {
    MutationRequest {
        plan,
        idempotency_key: key,
        claims,
        record_id: Some(record_id),
        expected_etag: Some(expected_etag),
        body: MutationBody::Patch(vec![PatchOperation::Replace {
            path: "/data/label".to_owned(),
            value: Value::String(label.to_owned()),
        }]),
        response_fields: response_fields(),
        representation: registry_breg::record_profile::RecordRepresentation::Json,
        correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
    }
}

fn tombstone_request<'a>(
    plan: &'a MutationPlan,
    key: &'a str,
    claims: &'a ClaimContext,
    record_id: &'a str,
    expected_etag: &'a str,
) -> MutationRequest<'a> {
    MutationRequest {
        plan,
        idempotency_key: key,
        claims,
        record_id: Some(record_id),
        expected_etag: Some(expected_etag),
        body: MutationBody::Tombstone,
        response_fields: response_fields(),
        representation: registry_breg::record_profile::RecordRepresentation::Json,
        correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
    }
}

fn response_fields() -> BTreeSet<String> {
    BTreeSet::from(["label".to_owned(), "quantity".to_owned()])
}

fn response_id(outcome: &MutationOutcome) -> String {
    let body: Value =
        serde_json::from_slice(outcome.response().body()).expect("mutation response is JSON");
    body["data"]["recordIdentifier"]
        .as_str()
        .expect("response includes id")
        .to_owned()
}

fn response_revision(outcome: &MutationOutcome) -> i64 {
    let body: Value =
        serde_json::from_slice(outcome.response().body()).expect("mutation response is JSON");
    body["data"]["revisionIdentifier"]
        .as_str()
        .and_then(|value| value.parse::<i64>().ok())
        .expect("response includes revision")
}

fn response_header(outcome: &MutationOutcome, header: PermittedResponseHeader) -> String {
    String::from_utf8(outcome.response().headers()[&header].clone()).expect("header is UTF-8")
}

fn response_etag(
    profile: &AuditProfile,
    claims: &ClaimContext,
    package_revision: &str,
    record_id: &str,
    record_revision: i64,
    response_fields: &BTreeSet<String>,
) -> String {
    let authorization_context = canonical_claim_context(profile, claims, package_revision);
    let etag_input = canonicalize_json(&json!({
        "authorizationContext": authorization_context,
        "packageRevision": package_revision,
        "recordId": record_id,
        "recordRevision": record_revision,
        "responseFields": response_fields,
        "responseRepresentation": "application/json",
    }))
    .expect("etag input is canonical");
    let etag_input = std::str::from_utf8(&etag_input).expect("canonical JSON is UTF-8");
    let hash = profile
        .key_hasher()
        .audit_reference_hash("breg-response-etag-v1", package_revision, etag_input)
        .expect("etag reference hashes");
    format!("\"breg-{hash}\"")
}

fn canonical_claim_context(
    profile: &AuditProfile,
    context: &ClaimContext,
    package_revision: &str,
) -> Value {
    let principal_reference = profile
        .key_hasher()
        .audit_reference_hash(
            "breg-principal-v1",
            package_revision,
            context.principal().expect("principal is present"),
        )
        .expect("principal reference hashes");
    let row_boundaries = context
        .row_boundaries()
        .iter()
        .map(|boundary| {
            let reference_context = format!(
                "{package_revision}:{}:{}",
                boundary.field(),
                boundary.operator().as_str()
            );
            let value_references = boundary
                .values()
                .into_iter()
                .map(|value| {
                    profile.key_hasher().audit_reference_hash(
                        "breg-row-boundary-value-v1",
                        &reference_context,
                        value,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .expect("row-boundary references hash");
            json!({
                "field": boundary.field(),
                "operator": boundary.operator().as_str(),
                "valueReferences": value_references,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "entityId": context.entity_id(),
        "principalReference": principal_reference,
        "selectedAccessProfile": context.access_profile(),
        "verifiedPurpose": context.purpose(),
        "rowBoundaries": row_boundaries,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DurableCounts {
    current: i64,
    revisions: i64,
    outbox: i64,
    audit: i64,
    idempotency: i64,
}

fn assert_one_complete_effect(before: DurableCounts, after: DurableCounts, current_delta: i64) {
    assert_eq!(
        after,
        DurableCounts {
            current: before.current + current_delta,
            revisions: before.revisions + 1,
            outbox: before.outbox + 1,
            audit: before.audit + 2,
            idempotency: before.idempotency + 1,
        }
    );
}

fn assert_audited_replay_only(before: DurableCounts, after: DurableCounts) {
    assert_eq!(
        after,
        DurableCounts {
            audit: before.audit + 2,
            ..before
        }
    );
}

fn assert_audited_refusal_only(before: DurableCounts, after: DurableCounts) {
    assert_eq!(
        after,
        DurableCounts {
            audit: before.audit + 2,
            ..before
        }
    );
}

async fn durable_counts(database: &TestDatabase, table: &str) -> DurableCounts {
    let row = database
        .admin
        .query_one(
            &format!(
                "SELECT
                   (SELECT count(*) FROM registry_data.\"{table}\"),
                   (SELECT count(*) FROM registry_internal.registry_revisions),
                   (SELECT count(*) FROM registry_internal.registry_outbox),
                   (SELECT count(*) FROM registry_internal.registry_audit),
                   (SELECT count(*) FROM registry_internal.registry_idempotency)"
            ),
            &[],
        )
        .await
        .expect("administrator can inspect durable state");
    DurableCounts {
        current: row.get(0),
        revisions: row.get(1),
        outbox: row.get(2),
        audit: row.get(3),
        idempotency: row.get(4),
    }
}

async fn assert_current_row_tombstoned(database: &TestDatabase, table: &str, record_id: &str) {
    let lifecycle: String = database
        .admin
        .query_one(
            &format!(
                "SELECT record_lifecycle FROM registry_data.\"{table}\"
                 WHERE record_id = $1::text::uuid"
            ),
            &[&record_id],
        )
        .await
        .expect("administrator can inspect current row")
        .get(0);
    assert_eq!(lifecycle, "tombstoned");
}

async fn assert_current_row_active(database: &TestDatabase, table: &str, record_id: &str) {
    let lifecycle: String = database
        .admin
        .query_one(
            &format!(
                "SELECT record_lifecycle FROM registry_data.\"{table}\"
                 WHERE record_id = $1::text::uuid"
            ),
            &[&record_id],
        )
        .await
        .expect("administrator can inspect current row")
        .get(0);
    assert_eq!(lifecycle, "active");
}

async fn assert_three_revisions_one_record_across_package_upgrade(
    database: &TestDatabase,
    record_id: &str,
) {
    let rows = database
        .admin
        .query(
            "SELECT record_id::text, record_reference, record_revision,
                    predecessor_revision, record_lifecycle, package_revision,
                    operation_id, mutation_kind, snapshot
             FROM registry_internal.registry_revisions
             WHERE entity_id = 'widget'
             ORDER BY record_revision",
            &[],
        )
        .await
        .expect("administrator can inspect revisions");
    assert_eq!(rows.len(), 3);
    let mut references = BTreeSet::new();
    for row in &rows {
        assert!(row.get::<_, String>(0) == record_id);
        references.insert(row.get::<_, String>(1));
    }
    assert!(references.len() >= 2);
    assert_eq!(rows[0].get::<_, i64>(2), 1);
    assert_eq!(rows[0].get::<_, Option<i64>>(3), None);
    assert_eq!(rows[0].get::<_, String>(4), "active");
    assert_eq!(rows[0].get::<_, String>(5), "package-tombstone-1");
    assert_eq!(rows[0].get::<_, String>(6), "records.widget.create");
    assert_eq!(rows[0].get::<_, String>(7), "create");
    assert_eq!(rows[1].get::<_, i64>(2), 2);
    assert_eq!(rows[1].get::<_, Option<i64>>(3), Some(1));
    assert_eq!(rows[1].get::<_, String>(5), "package-tombstone-2");
    assert_eq!(rows[1].get::<_, String>(7), "patch");
    assert_eq!(rows[2].get::<_, i64>(2), 3);
    assert_eq!(rows[2].get::<_, Option<i64>>(3), Some(2));
    assert_eq!(rows[2].get::<_, String>(4), "tombstoned");
    assert_eq!(rows[2].get::<_, String>(5), "package-tombstone-2");
    assert_eq!(rows[2].get::<_, String>(6), "records.widget.tombstone");
    assert_eq!(rows[2].get::<_, String>(7), "tombstone");
    assert!(
        rows[2].get::<_, Vec<u8>>(8)
            == br#"{"jurisdiction":"zone-a","label":"patched-label","quantity":7}"#.as_slice(),
        "canonical tombstone revision snapshot did not match expected bytes"
    );
}

async fn assert_tombstone_event_is_canonical(database: &TestDatabase, record_id: &str) {
    let row = database
        .admin
        .query_one(
            "SELECT event_id::text, event_type, trigger, entity_id, record_revision,
                    package_revision, schema_fingerprint, payload
             FROM registry_internal.registry_outbox
             WHERE event_type = 'widget-tombstoned'",
            &[],
        )
        .await
        .expect("administrator can inspect outbox");
    let event_id: String = row.get(0);
    assert_eq!(event_id.len(), 36);
    assert_eq!(row.get::<_, String>(1), "widget-tombstoned");
    assert_eq!(row.get::<_, String>(2), "tombstoned");
    assert_eq!(row.get::<_, String>(3), "widget");
    assert_eq!(row.get::<_, i64>(4), 3);
    assert_eq!(row.get::<_, String>(5), "package-tombstone-2");
    assert!(row.get::<_, String>(6).starts_with("sha256:"));
    let expected_payload = canonicalize_json(&json!({
        "entity": "widget",
        "recordId": record_id,
        "revision": 3,
        "trigger": "tombstoned",
        "packageRevision": "package-tombstone-2",
        "values": {
            "label": "patched-label",
            "quantity": 7,
        },
    }))
    .expect("expected tombstone event canonicalizes");
    assert!(
        row.get::<_, Vec<u8>>(7) == expected_payload.as_slice(),
        "canonical tombstone outbox projection did not match expected bytes"
    );
}

async fn tombstone_event_id(database: &TestDatabase) -> String {
    database
        .admin
        .query_one(
            "SELECT event_id::text
             FROM registry_internal.registry_outbox
             WHERE event_type = 'widget-tombstoned'",
            &[],
        )
        .await
        .expect("administrator can inspect event id")
        .get(0)
}

async fn assert_revision_provenance_is_keyed(database: &TestDatabase) {
    let rows = database
        .admin
        .query(
            "SELECT principal_reference, request_reference
             FROM registry_internal.registry_revisions",
            &[],
        )
        .await
        .expect("administrator can inspect revision provenance");
    assert!(!rows.is_empty());
    let mut requests = BTreeSet::new();
    for row in rows {
        let principal: String = row.get(0);
        let request: String = row.get(1);
        assert_eq!(principal.len(), 76);
        assert_eq!(request.len(), 76);
        assert!(principal.starts_with("hmac-sha256:"));
        assert!(request.starts_with("hmac-sha256:"));
        assert!(!principal.contains(PRINCIPAL_CANARY));
        assert!(!request.contains(IDEMPOTENCY_CANARY));
        requests.insert(request);
    }
    assert!(requests.len() >= 3);
}

async fn assert_audit_excludes_raw_values(database: &TestDatabase, forbidden: &[&str]) {
    let rows = database
        .admin
        .query("SELECT envelope FROM registry_internal.registry_audit", &[])
        .await
        .expect("administrator can inspect audit");
    let audit_text = rows
        .iter()
        .map(|row| String::from_utf8(row.get::<_, Vec<u8>>(0)).expect("audit is UTF-8"))
        .collect::<Vec<_>>()
        .join("\n");
    for value in forbidden {
        assert!(!audit_text.contains(value));
    }
}
