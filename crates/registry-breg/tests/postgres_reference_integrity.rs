// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::BTreeSet;
use std::time::Duration;

use deadpool_postgres::Client as PooledClient;
use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::idempotency::PermittedResponseHeader;
use registry_breg::mutation::{
    BatchMutationItem, BatchMutationRequest, MutationBody, MutationError, MutationOutcome,
    MutationPlan, MutationRequest, MutationTransaction, PatchOperation,
};
use registry_breg::postgres::{
    begin_record_transaction, initialize_compiled_registry_state_for_test, install_compiled_schema,
    ClaimContext, ExpectedRegistryIdentity, RegistryLockKey, RegistryStateTestIdentity,
    RowBoundaryContext, RuntimePool,
};
use registry_platform_audit::AuditProfile;
use serde_json::{Map, Value};
use tokio_postgres::Client;
use uuid::Uuid;

const PACKAGE_ID: &str = "reference-integrity-registry";
const DATABASE_ID: &str = "reference-integrity-database";
const INSTANCE_ID: &str = "reference-integrity-instance";
const PRINCIPAL: &str = "reference-integrity-principal";

struct Fixture {
    database: TestDatabase,
    registry: registry_breg::CompiledRegistry,
    identity: ExpectedRegistryIdentity,
    pool: RuntimePool,
    mutations: MutationTransaction,
}

impl Fixture {
    async fn start(pool_size: usize) -> Self {
        Self::start_with(pool_size, compiled_registry()).await
    }

    async fn start_with(pool_size: usize, registry: registry_breg::CompiledRegistry) -> Self {
        let database = TestDatabase::create(pool_size).await;
        let (migration, migration_task) = database.connect_migration().await;
        install_compiled_schema(&migration, &registry, &database.runtime_role)
            .await
            .expect("migration installs active-reference constraints");
        let identity = initialize_compiled_registry_state_for_test(
            &migration,
            &database.runtime_role,
            &registry,
            RegistryStateTestIdentity {
                package_id: PACKAGE_ID,
                database_id: DATABASE_ID,
                label: "reference-integrity-package-1",
            },
        )
        .await
        .expect("migration initializes the active package identity");
        migration_task.abort();

        let pool = database
            .runtime_config
            .build_pool()
            .expect("bounded runtime pool builds");
        let mutations = MutationTransaction::new(
            RegistryLockKey::derive(PACKAGE_ID).expect("registry lock key is bounded"),
            Duration::from_secs(5),
            identity.clone(),
            INSTANCE_ID,
            database.audit(
                AuditProfile::production_from_secret_bytes(vec![0x55; 32].into())
                    .expect("test owns a keyed audit profile"),
            ),
        );
        Self {
            database,
            registry,
            identity,
            pool,
            mutations,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn active_references_refuse_tombstones_and_preserve_retained_links() {
    let fixture = Fixture::start(10).await;
    let target_create = plan(&fixture, "records.target.create");
    let target_patch = plan(&fixture, "records.target.patch");
    let target_tombstone = plan(&fixture, "records.target.tombstone");
    let source_create = plan(&fixture, "records.source.create");
    let source_patch = plan(&fixture, "records.source.patch");
    let source_tombstone = plan(&fixture, "records.source.tombstone");
    let source_batch = plan(&fixture, "records.source.batch");
    let target_claims = claims(&fixture.registry, "target", "target-operator", "zone-a");
    let source_claims = claims(&fixture.registry, "source", "linker", "zone-b");
    assert!(
        !fixture.registry.entities()["target"]
            .access_profiles
            .contains_key("linker"),
        "the source writer has no direct target Record grant"
    );

    let mut target_client = fixture.pool.get_for_test().await.expect("target client");
    let mut source_client = fixture.pool.get_for_test().await.expect("source client");

    let target = create_target(
        &fixture.mutations,
        &mut target_client,
        &target_create,
        &target_claims,
        "target-main",
        "main",
    )
    .await;
    let target_id = response_id(&target);
    let target_etag = response_etag(&target);
    let source = create_source(
        &fixture.mutations,
        &mut source_client,
        &source_create,
        &source_claims,
        "source-main",
        &target_id,
        None,
    )
    .await
    .expect("link-only CRUD accepts an active target and a null optional reference");
    let source_id = response_id(&source);
    let source_etag = response_etag(&source);

    assert_source_hidden_from_target_profile(&fixture, &target_claims, &source_id).await;
    let refused = tombstone(
        &fixture.mutations,
        &mut target_client,
        &target_tombstone,
        &target_claims,
        "target-main-refused",
        &target_id,
        &target_etag,
        &["jurisdiction", "name", "related"],
    )
    .await
    .expect_err("an active hidden source prevents target tombstoning");
    assert_value_free_conflict(refused, &fixture.registry, &[&target_id, &source_id]);
    assert_record(&fixture, "target", &target_id, "active", 1).await;

    tombstone(
        &fixture.mutations,
        &mut source_client,
        &source_tombstone,
        &source_claims,
        "source-main-tombstone",
        &source_id,
        &source_etag,
        &["jurisdiction", "name", "target", "alternate"],
    )
    .await
    .expect("tombstoning the source releases its active-reference restriction");
    tombstone(
        &fixture.mutations,
        &mut target_client,
        &target_tombstone,
        &target_claims,
        "target-main-tombstone",
        &target_id,
        &target_etag,
        &["jurisdiction", "name", "related"],
    )
    .await
    .expect("the formerly referenced target can now be tombstoned");
    assert_retained_reference(&fixture, &source_id, &target_id).await;
    assert!(
        fixture
            .database
            .admin
            .execute(
                &format!(
                    "DELETE FROM registry_data.{} WHERE record_id = $1",
                    q(&fixture.registry.entities()["target"].physical_table)
                ),
                &[&Uuid::parse_str(&target_id).expect("target id is a UUID")],
            )
            .await
            .is_err(),
        "the raw FK preserves a tombstoned source's retained UUID"
    );

    let stable = create_target(
        &fixture.mutations,
        &mut target_client,
        &target_create,
        &target_claims,
        "target-stable",
        "stable",
    )
    .await;
    let stable_id = response_id(&stable);
    let old = create_target(
        &fixture.mutations,
        &mut target_client,
        &target_create,
        &target_claims,
        "target-old",
        "old",
    )
    .await;
    let old_id = response_id(&old);
    let old_etag = response_etag(&old);
    let replacement = create_target(
        &fixture.mutations,
        &mut target_client,
        &target_create,
        &target_claims,
        "target-replacement",
        "replacement",
    )
    .await;
    let replacement_id = response_id(&replacement);

    let clearable = create_source(
        &fixture.mutations,
        &mut source_client,
        &source_create,
        &source_claims,
        "source-clearable",
        &stable_id,
        Some(&old_id),
    )
    .await
    .expect("source with an optional active reference is created");
    let clearable_id = response_id(&clearable);
    let clearable_etag = response_etag(&clearable);
    let cleared = patch(
        &fixture.mutations,
        &mut source_client,
        &source_patch,
        &source_claims,
        "source-clear",
        &clearable_id,
        &clearable_etag,
        vec![PatchOperation::Remove {
            path: "/data/alternate".to_owned(),
        }],
    )
    .await
    .expect("clearing an optional reference commits");
    tombstone(
        &fixture.mutations,
        &mut target_client,
        &target_tombstone,
        &target_claims,
        "target-old-after-clear",
        &old_id,
        &old_etag,
        &["jurisdiction", "name", "related"],
    )
    .await
    .expect("clearing the final active reference permits target tombstoning");

    let repoint_old = create_target(
        &fixture.mutations,
        &mut target_client,
        &target_create,
        &target_claims,
        "target-repoint-old",
        "repoint-old",
    )
    .await;
    let repoint_old_id = response_id(&repoint_old);
    let repoint_old_etag = response_etag(&repoint_old);
    let repointable = create_source(
        &fixture.mutations,
        &mut source_client,
        &source_create,
        &source_claims,
        "source-repointable",
        &stable_id,
        Some(&repoint_old_id),
    )
    .await
    .expect("source to repoint is created");
    let repointable_id = response_id(&repointable);
    let repointed = patch(
        &fixture.mutations,
        &mut source_client,
        &source_patch,
        &source_claims,
        "source-repoint",
        &repointable_id,
        &response_etag(&repointable),
        vec![PatchOperation::Replace {
            path: "/data/alternate".to_owned(),
            value: Value::String(replacement_id.clone()),
        }],
    )
    .await
    .expect("repointing to another active target commits");
    assert_eq!(response_revision(&repointed), 2);
    tombstone(
        &fixture.mutations,
        &mut target_client,
        &target_tombstone,
        &target_claims,
        "target-repoint-old-tombstone",
        &repoint_old_id,
        &repoint_old_etag,
        &["jurisdiction", "name", "related"],
    )
    .await
    .expect("repointing permits the old target to be tombstoned");

    let self_linked = create_target(
        &fixture.mutations,
        &mut target_client,
        &target_create,
        &target_claims,
        "target-self-linked",
        "self-linked",
    )
    .await;
    let self_linked_id = response_id(&self_linked);
    let self_linked = patch_target(
        &fixture.mutations,
        &mut target_client,
        &target_patch,
        &target_claims,
        "target-self-link",
        &self_linked_id,
        &response_etag(&self_linked),
        &self_linked_id,
    )
    .await
    .expect("an active target may refer to itself");
    tombstone(
        &fixture.mutations,
        &mut target_client,
        &target_tombstone,
        &target_claims,
        "target-self-linked-tombstone",
        &self_linked_id,
        &response_etag(&self_linked),
        &["jurisdiction", "name", "related"],
    )
    .await
    .expect("a self-reference released by the same update does not block tombstoning");

    let cycle_left = create_target(
        &fixture.mutations,
        &mut target_client,
        &target_create,
        &target_claims,
        "target-cycle-left",
        "cycle-left",
    )
    .await;
    let cycle_left_id = response_id(&cycle_left);
    let cycle_right = create_target(
        &fixture.mutations,
        &mut target_client,
        &target_create,
        &target_claims,
        "target-cycle-right",
        "cycle-right",
    )
    .await;
    let cycle_right_id = response_id(&cycle_right);
    let cycle_left = patch_target(
        &fixture.mutations,
        &mut target_client,
        &target_patch,
        &target_claims,
        "target-cycle-left-link",
        &cycle_left_id,
        &response_etag(&cycle_left),
        &cycle_right_id,
    )
    .await
    .expect("the first side of an active cycle commits");
    let cycle_right = patch_target(
        &fixture.mutations,
        &mut target_client,
        &target_patch,
        &target_claims,
        "target-cycle-right-link",
        &cycle_right_id,
        &response_etag(&cycle_right),
        &cycle_left_id,
    )
    .await
    .expect("the second side of an active cycle commits");
    for (key, id, etag, incoming) in [
        (
            "target-cycle-left-tombstone",
            cycle_left_id.as_str(),
            response_etag(&cycle_left),
            cycle_right_id.as_str(),
        ),
        (
            "target-cycle-right-tombstone",
            cycle_right_id.as_str(),
            response_etag(&cycle_right),
            cycle_left_id.as_str(),
        ),
    ] {
        let error = tombstone(
            &fixture.mutations,
            &mut target_client,
            &target_tombstone,
            &target_claims,
            key,
            id,
            &etag,
            &["jurisdiction", "name", "related"],
        )
        .await
        .expect_err("an incoming row in an active cycle prevents tombstoning");
        assert_value_free_conflict(error, &fixture.registry, &[id, incoming]);
    }
    assert_record(&fixture, "target", &cycle_left_id, "active", 2).await;
    assert_record(&fixture, "target", &cycle_right_id, "active", 2).await;

    let dead = create_target(
        &fixture.mutations,
        &mut target_client,
        &target_create,
        &target_claims,
        "target-dead",
        "dead",
    )
    .await;
    let dead_id = response_id(&dead);
    tombstone(
        &fixture.mutations,
        &mut target_client,
        &target_tombstone,
        &target_claims,
        "target-dead-tombstone",
        &dead_id,
        &response_etag(&dead),
        &["jurisdiction", "name", "related"],
    )
    .await
    .expect("unreferenced target is tombstoned for negative writes");

    let before_create = durable_state(&fixture).await;
    let inactive_create = create_source(
        &fixture.mutations,
        &mut source_client,
        &source_create,
        &source_claims,
        "source-inactive-create",
        &dead_id,
        None,
    )
    .await
    .expect_err("create refuses a tombstoned target");
    assert_value_free_conflict(inactive_create, &fixture.registry, &[&dead_id]);
    assert_eq!(durable_state(&fixture).await, before_create);

    let before_patch = durable_state(&fixture).await;
    let inactive_patch = patch(
        &fixture.mutations,
        &mut source_client,
        &source_patch,
        &source_claims,
        "source-inactive-patch",
        &clearable_id,
        &response_etag(&cleared),
        vec![PatchOperation::Add {
            path: "/data/alternate".to_owned(),
            value: Value::String(dead_id.clone()),
        }],
    )
    .await
    .expect_err("patch refuses a tombstoned target");
    assert_value_free_conflict(
        inactive_patch,
        &fixture.registry,
        &[&dead_id, &clearable_id],
    );
    assert_eq!(durable_state(&fixture).await, before_patch);

    let before_batch = durable_state(&fixture).await;
    let inactive_batch = fixture
        .mutations
        .execute_batch(
            &mut source_client,
            BatchMutationRequest {
                plan: &source_batch,
                idempotency_key: "source-inactive-batch",
                claims: &source_claims,
                change_context: None,
                items: vec![BatchMutationItem::Create(source_data(
                    "batch-inactive",
                    &dead_id,
                    None,
                ))],
                response_fields: source_fields(),
                body_bytes: 256,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
                ingestion: None,
            },
        )
        .await
        .expect_err("batch create shares the active-reference refusal");
    assert_value_free_conflict(inactive_batch, &fixture.registry, &[&dead_id]);
    assert_eq!(durable_state(&fixture).await, before_batch);

    fixture.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn occurrence_references_restrict_tombstone_and_mutable_source_control() {
    let fixture = Fixture::start_with(10, occurrence_registry()).await;
    let subject_create = plan(&fixture, "records.subject.create");
    let subject_tombstone = plan(&fixture, "records.subject.tombstone");
    let decision_create = plan(&fixture, "records.decision.create");
    let journal_create = plan(&fixture, "records.journal.create");
    let journal_tombstone = plan(&fixture, "records.journal.tombstone");
    assert!(
        MutationPlan::from_compiled(&fixture.registry, "records.decision.tombstone").is_err(),
        "a create-only occurrence record has no tombstone operation"
    );
    assert!(
        MutationPlan::from_compiled(&fixture.registry, "records.decision.patch").is_err(),
        "a create-only occurrence record has no patch operation"
    );
    let subject_claims = claims(&fixture.registry, "subject", "subject-operator", "zone-a");
    let recorder_claims = claims(&fixture.registry, "decision", "recorder", "zone-a");
    let journal_claims = claims(&fixture.registry, "journal", "recorder", "zone-a");
    let mut client = fixture.pool.get_for_test().await.expect("client");
    let subject_fields: BTreeSet<String> = ["jurisdiction", "name"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let decision_fields: BTreeSet<String> = ["jurisdiction", "subject", "corrects", "occurred-on"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let journal_fields: BTreeSet<String> = ["jurisdiction", "subject", "noted-on"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let make_subject = |name: &str| {
        Map::from_iter([
            (
                "jurisdiction".to_owned(),
                Value::String("zone-a".to_owned()),
            ),
            ("name".to_owned(), Value::String(name.to_owned())),
        ])
    };
    let make_decision = |subject: &str, corrects: Option<&str>| {
        let mut data = Map::from_iter([
            (
                "jurisdiction".to_owned(),
                Value::String("zone-a".to_owned()),
            ),
            ("subject".to_owned(), Value::String(subject.to_owned())),
            (
                "occurredOn".to_owned(),
                Value::String("2026-10-20".to_owned()),
            ),
        ]);
        if let Some(id) = corrects {
            data.insert("corrects".to_owned(), Value::String(id.to_owned()));
        }
        data
    };
    let make_journal = |subject: &str| {
        Map::from_iter([
            (
                "jurisdiction".to_owned(),
                Value::String("zone-a".to_owned()),
            ),
            ("subject".to_owned(), Value::String(subject.to_owned())),
            ("notedOn".to_owned(), Value::String("2026-10-21".to_owned())),
        ])
    };

    let subject = fixture
        .mutations
        .execute(
            &mut client,
            create_request(
                &subject_create,
                "subject-1",
                &subject_claims,
                make_subject("subject one"),
                subject_fields.clone(),
            ),
        )
        .await
        .expect("subject create commits");
    let subject_id = response_id(&subject);
    let subject_etag = response_etag(&subject);

    // A correction is a second occurrence that names the first; the first
    // keeps its single revision and its content.
    let original = fixture
        .mutations
        .execute(
            &mut client,
            create_request(
                &decision_create,
                "decision-1",
                &recorder_claims,
                make_decision(&subject_id, None),
                decision_fields.clone(),
            ),
        )
        .await
        .expect("occurrence create commits");
    let original_id = response_id(&original);
    let correction = fixture
        .mutations
        .execute(
            &mut client,
            create_request(
                &decision_create,
                "decision-2",
                &recorder_claims,
                make_decision(&subject_id, Some(&original_id)),
                decision_fields.clone(),
            ),
        )
        .await
        .expect("correction create commits");
    assert_ne!(response_id(&correction), original_id);
    assert_eq!(
        response_json(&correction)["data"]["domainData"]["corrects"],
        original_id
    );
    assert_record(&fixture, "decision", &original_id, "active", 1).await;

    // A correction of a record that does not exist is refused whole.
    let rows_before = decision_rows(&fixture).await;
    let missing = Uuid::new_v4().to_string();
    let refused = fixture
        .mutations
        .execute(
            &mut client,
            create_request(
                &decision_create,
                "decision-missing",
                &recorder_claims,
                make_decision(&subject_id, Some(&missing)),
                decision_fields.clone(),
            ),
        )
        .await
        .expect_err("a correction names an existing occurrence");
    assert!(
        !format!("{refused:?} {refused}").contains(&missing),
        "the refusal carries no submitted identifier"
    );
    assert_eq!(decision_rows(&fixture).await, rows_before);

    // Occurrence references restrict tombstoning the subject. The occurrence
    // is create-only, so the restriction cannot be released.
    let refused = tombstone(
        &fixture.mutations,
        &mut client,
        &subject_tombstone,
        &subject_claims,
        "subject-1-refused",
        &subject_id,
        &subject_etag,
        &["jurisdiction", "name"],
    )
    .await
    .expect_err("an occurrence that references the subject prevents its tombstone");
    assert_value_free_conflict(refused, &fixture.registry, &[&subject_id, &original_id]);
    assert_record(&fixture, "subject", &subject_id, "active", 1).await;

    // A mutable record that maps an occurrence restricts the same way, and
    // tombstoning it releases the restriction while its link stays stored.
    let held = fixture
        .mutations
        .execute(
            &mut client,
            create_request(
                &subject_create,
                "subject-2",
                &subject_claims,
                make_subject("subject two"),
                subject_fields.clone(),
            ),
        )
        .await
        .expect("second subject create commits");
    let held_id = response_id(&held);
    let held_etag = response_etag(&held);
    let journal = fixture
        .mutations
        .execute(
            &mut client,
            create_request(
                &journal_create,
                "journal-1",
                &journal_claims,
                make_journal(&held_id),
                journal_fields,
            ),
        )
        .await
        .expect("mutable occurrence source create commits");
    let journal_id = response_id(&journal);
    let journal_etag = response_etag(&journal);
    let refused = tombstone(
        &fixture.mutations,
        &mut client,
        &subject_tombstone,
        &subject_claims,
        "subject-2-refused",
        &held_id,
        &held_etag,
        &["jurisdiction", "name"],
    )
    .await
    .expect_err("an active mutable source prevents the subject tombstone");
    assert_value_free_conflict(refused, &fixture.registry, &[&held_id, &journal_id]);
    tombstone(
        &fixture.mutations,
        &mut client,
        &journal_tombstone,
        &journal_claims,
        "journal-1-tombstone",
        &journal_id,
        &journal_etag,
        &["jurisdiction", "subject", "noted-on"],
    )
    .await
    .expect("tombstoning the mutable source releases its restriction");
    tombstone(
        &fixture.mutations,
        &mut client,
        &subject_tombstone,
        &subject_claims,
        "subject-2-tombstone",
        &held_id,
        &held_etag,
        &["jurisdiction", "name"],
    )
    .await
    .expect("the formerly referenced subject can now be tombstoned");
    let journal_entity = &fixture.registry.entities()["journal"];
    let retained: Uuid = fixture
        .database
        .admin
        .query_one(
            &format!(
                "SELECT {} FROM registry_data.{} WHERE record_id = $1",
                q(&journal_entity.fields["subject"].physical_name),
                q(&journal_entity.physical_table)
            ),
            &[&Uuid::parse_str(&journal_id).expect("journal id is a UUID")],
        )
        .await
        .expect("administrator reads the retained reference")
        .get(0);
    assert_eq!(retained.to_string(), held_id);
    assert!(
        fixture
            .database
            .admin
            .execute(
                &format!(
                    "DELETE FROM registry_data.{} WHERE record_id = $1",
                    q(&fixture.registry.entities()["subject"].physical_table)
                ),
                &[&Uuid::parse_str(&held_id).expect("subject id is a UUID")],
            )
            .await
            .is_err(),
        "the raw FK preserves the tombstoned source's retained UUID"
    );
    fixture.database.cleanup().await;
}

async fn decision_rows(fixture: &Fixture) -> i64 {
    fixture
        .database
        .admin
        .query_one(
            &format!(
                "SELECT count(*) FROM registry_data.{}",
                q(&fixture.registry.entities()["decision"].physical_table)
            ),
            &[],
        )
        .await
        .expect("administrator counts occurrence rows")
        .get(0)
}

fn occurrence_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"reference-integrity-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "datasets":[{"id":"records"}],
          "recordTypes":[{
            "id":"subject","primaryDataset":"records","route":"subjects","mutationMode":"mutable","tombstone":true,"classification":"internal",
            "fields":[
              {"id":"jurisdiction","type":"string","maximumLength":32,"required":true,"classification":"internal"},
              {"id":"name","type":"string","maximumLength":64,"required":true,"classification":"internal"}
            ]
          },{
            "id":"decision","primaryDataset":"records","route":"decisions","mutationMode":"create-only","classification":"internal",
            "fields":[
              {"id":"jurisdiction","type":"string","maximumLength":32,"required":true,"classification":"internal"},
              {"id":"subject","type":"reference","target":"subject","onDelete":"restrict","required":true,"classification":"internal"},
              {"id":"corrects","type":"reference","target":"decision","onDelete":"restrict","classification":"internal"},
              {"id":"occurred-on","type":"date","required":true,"classification":"internal"}
            ],
            "occurrence":{
              "label":"Decision made",
              "subjects":[{"role":"subject","field":"subject","label":"Subject","target":"subject"}],
              "occurredAt":{"at":"occurred-on"},
              "correction":{"field":"corrects","relation":"corrects"}
            }
          },{
            "id":"journal","primaryDataset":"records","route":"journals","mutationMode":"mutable","tombstone":true,"classification":"internal",
            "fields":[
              {"id":"jurisdiction","type":"string","maximumLength":32,"required":true,"classification":"internal"},
              {"id":"subject","type":"reference","target":"subject","onDelete":"restrict","required":true,"classification":"internal"},
              {"id":"noted-on","type":"date","required":true,"classification":"internal"}
            ],
            "occurrence":{
              "label":"Note made",
              "subjects":[{"role":"subject","field":"subject","label":"Subject","target":"subject"}],
              "occurredAt":{"at":"noted-on"}
            }
          }],
          "accessProfiles":[{
            "id":"subject-operator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","requiredPurposes":["operations"],
            "permissions":{"records":[{
              "recordType":"subject","operations":["create","get","patch","tombstone"],
              "readableFields":["jurisdiction","name"],"writableFields":["jurisdiction","name"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]}
          },{
            "id":"recorder","principalClaim":"principal","requiredScopes":"unrestricted","requiredPurposes":["operations"],
            "permissions":{"records":[{
              "recordType":"decision","operations":["create","get"],
              "readableFields":["jurisdiction","subject","corrects","occurred-on"],
              "writableFields":["jurisdiction","subject","corrects","occurred-on"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            },{
              "recordType":"journal","operations":["create","get","patch","tombstone"],
              "readableFields":["jurisdiction","subject","noted-on"],
              "writableFields":["jurisdiction","subject","noted-on"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]}
          }]
        }"#,
    )
    .expect("occurrence reference fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("occurrence reference fixture compiles")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn active_reference_races_never_commit_a_broken_lifecycle() {
    let fixture = Fixture::start(10).await;
    let target_create = plan(&fixture, "records.target.create");
    let target_tombstone = plan(&fixture, "records.target.tombstone");
    let source_create = plan(&fixture, "records.source.create");
    let source_patch = plan(&fixture, "records.source.patch");
    let target_claims = claims(&fixture.registry, "target", "target-operator", "zone-a");
    let source_claims = claims(&fixture.registry, "source", "linker", "zone-b");

    let mut target_client = fixture.pool.get_for_test().await.expect("target client");
    let mut source_client = fixture.pool.get_for_test().await.expect("source client");
    let (observer, observer_task) = fixture.database.connect_migration().await;
    let target_pid = backend_pid(&target_client).await;
    let source_pid = backend_pid(&source_client).await;
    let barrier_pid = backend_pid(&fixture.database.admin).await;
    let target_table = q(&fixture.registry.entities()["target"].physical_table);
    let source_table = q(&fixture.registry.entities()["source"].physical_table);
    let source_alternate =
        q(&fixture.registry.entities()["source"].fields["alternate"].physical_name);

    fixture
        .database
        .admin
        .batch_execute(&format!(
            "CREATE FUNCTION registry_internal.pause_target_tombstone() RETURNS trigger
               LANGUAGE plpgsql AS $body$
               BEGIN PERFORM pg_advisory_xact_lock(2250001); RETURN NEW; END $body$;
             CREATE TRIGGER pause_target_tombstone
               BEFORE UPDATE OF record_lifecycle ON registry_data.{target_table}
               FOR EACH ROW WHEN (NEW.record_lifecycle = 'tombstoned')
               EXECUTE FUNCTION registry_internal.pause_target_tombstone()"
        ))
        .await
        .expect("test installs a target-first transaction barrier");
    fixture
        .database
        .admin
        .query_one("SELECT pg_advisory_lock(2250001)", &[])
        .await
        .expect("administrator holds the target-first barrier");

    {
        let target_first = create_target(
            &fixture.mutations,
            &mut target_client,
            &target_create,
            &target_claims,
            "race-target-first",
            "race-target-first",
        )
        .await;
        let target_first_id = response_id(&target_first);
        let target_first_etag = response_etag(&target_first);
        let target_tombstone_future = tombstone(
            &fixture.mutations,
            &mut target_client,
            &target_tombstone,
            &target_claims,
            "race-target-first-tombstone",
            &target_first_id,
            &target_first_etag,
            &["jurisdiction", "name", "related"],
        );
        tokio::pin!(target_tombstone_future);
        assert_waits_for(
            &observer,
            target_pid,
            barrier_pid,
            &mut target_tombstone_future,
            "target tombstone reaches its held transaction",
        )
        .await;

        let source_create_future = create_source(
            &fixture.mutations,
            &mut source_client,
            &source_create,
            &source_claims,
            "race-source-after-target",
            &target_first_id,
            None,
        );
        tokio::pin!(source_create_future);
        assert_waits_for(
            &observer,
            source_pid,
            target_pid,
            &mut source_create_future,
            "source create waits behind the target tombstone",
        )
        .await;
        fixture
            .database
            .admin
            .query_one("SELECT pg_advisory_unlock(2250001)", &[])
            .await
            .expect("administrator releases the target-first barrier");
        target_tombstone_future
            .await
            .expect("the target-first tombstone commits");
        let create_error = source_create_future
            .await
            .expect_err("the later source create cannot commit a dangling active reference");
        assert_value_free_conflict(create_error, &fixture.registry, &[&target_first_id]);
        assert_record(&fixture, "target", &target_first_id, "tombstoned", 2).await;
    }

    let stable = create_target(
        &fixture.mutations,
        &mut target_client,
        &target_create,
        &target_claims,
        "race-stable",
        "race-stable",
    )
    .await;
    let stable_id = response_id(&stable);
    let patch_target = create_target(
        &fixture.mutations,
        &mut target_client,
        &target_create,
        &target_claims,
        "race-patch-target",
        "race-patch-target",
    )
    .await;
    let patch_target_id = response_id(&patch_target);
    let patch_source = create_source(
        &fixture.mutations,
        &mut source_client,
        &source_create,
        &source_claims,
        "race-patch-source",
        &stable_id,
        None,
    )
    .await
    .expect("the hidden source is seeded for the source-first race");
    let patch_source_id = response_id(&patch_source);
    assert_source_hidden_from_target_profile(&fixture, &target_claims, &patch_source_id).await;

    fixture
        .database
        .admin
        .batch_execute(&format!(
            "CREATE FUNCTION registry_internal.pause_source_reference_patch() RETURNS trigger
               LANGUAGE plpgsql AS $body$
               BEGIN PERFORM pg_advisory_xact_lock(2250002); RETURN NEW; END $body$;
             CREATE TRIGGER zzzz_pause_source_reference_patch
               AFTER UPDATE ON registry_data.{source_table}
               FOR EACH ROW WHEN (OLD.{source_alternate} IS DISTINCT FROM NEW.{source_alternate})
               EXECUTE FUNCTION registry_internal.pause_source_reference_patch()"
        ))
        .await
        .expect("test installs a source-first transaction barrier");
    fixture
        .database
        .admin
        .query_one("SELECT pg_advisory_lock(2250002)", &[])
        .await
        .expect("administrator holds the source-first barrier");

    let patch_source_etag = response_etag(&patch_source);
    let source_patch_future = patch(
        &fixture.mutations,
        &mut source_client,
        &source_patch,
        &source_claims,
        "race-source-first-patch",
        &patch_source_id,
        &patch_source_etag,
        vec![PatchOperation::Add {
            path: "/data/alternate".to_owned(),
            value: Value::String(patch_target_id.clone()),
        }],
    );
    tokio::pin!(source_patch_future);
    assert_waits_for(
        &observer,
        source_pid,
        barrier_pid,
        &mut source_patch_future,
        "source patch reaches its held transaction after the FK check",
    )
    .await;

    let patch_target_etag = response_etag(&patch_target);
    let target_after_patch_future = tombstone(
        &fixture.mutations,
        &mut target_client,
        &target_tombstone,
        &target_claims,
        "race-target-after-source",
        &patch_target_id,
        &patch_target_etag,
        &["jurisdiction", "name", "related"],
    );
    tokio::pin!(target_after_patch_future);
    assert_waits_for(
        &observer,
        target_pid,
        source_pid,
        &mut target_after_patch_future,
        "target tombstone waits behind the hidden source patch",
    )
    .await;
    fixture
        .database
        .admin
        .query_one("SELECT pg_advisory_unlock(2250002)", &[])
        .await
        .expect("administrator releases the source-first barrier");
    source_patch_future
        .await
        .expect("the source-first patch commits its active reference");
    let tombstone_error = target_after_patch_future
        .await
        .expect_err("the later target tombstone cannot break the committed reference");
    assert_value_free_conflict(
        tombstone_error,
        &fixture.registry,
        &[&patch_target_id, &patch_source_id],
    );
    assert_record(&fixture, "target", &patch_target_id, "active", 1).await;
    assert_source_reference(
        &fixture,
        &patch_source_id,
        "alternate",
        Some(&patch_target_id),
    )
    .await;

    observer_task.abort();
    fixture.database.cleanup().await;
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"reference-integrity-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "datasets":[{"id":"records"}],
          "recordTypes":[{
            "id":"target","primaryDataset":"records","route":"targets","mutationMode":"mutable","tombstone":true,"classification":"internal",
            "fields":[
              {"id":"jurisdiction","type":"string","maximumLength":32,"required":true,"classification":"internal"},
              {"id":"name","type":"string","maximumLength":64,"required":true,"classification":"internal"},
              {"id":"related","type":"reference","target":"target","onDelete":"restrict","classification":"internal"}
            ]
          },{
            "id":"source","primaryDataset":"records","route":"sources","mutationMode":"mutable","tombstone":true,"classification":"internal",
            "batch":{"maximumItems":3,"maximumBytes":8192},
            "fields":[
              {"id":"jurisdiction","type":"string","maximumLength":32,"required":true,"classification":"internal"},
              {"id":"name","type":"string","maximumLength":64,"required":true,"classification":"internal"},
              {"id":"target","type":"reference","target":"target","onDelete":"restrict","required":true,"classification":"internal"},
              {"id":"alternate","type":"reference","target":"target","onDelete":"restrict","classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"target-operator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","requiredPurposes":["operations"],
            "permissions":{"records":[{
              "recordType":"target","operations":["create","get","patch","tombstone"],
              "readableFields":["jurisdiction","name","related"],"writableFields":["jurisdiction","name","related"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]}
          },{
            "id":"linker","principalClaim":"principal","requiredScopes":"unrestricted","requiredPurposes":["operations"],
            "permissions":{"records":[{
              "recordType":"source","operations":["create","get","patch","tombstone","batch"],
              "readableFields":["jurisdiction","name","target","alternate"],
              "writableFields":["jurisdiction","name","target","alternate"],
              "rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]
            }]}
          }]
        }"#,
    )
    .expect("reference-integrity fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("reference-integrity fixture compiles")
}

fn plan(fixture: &Fixture, route: &str) -> MutationPlan {
    MutationPlan::from_compiled(&fixture.registry, route).expect("mutation plan is compiled")
}

fn claims(
    registry: &registry_breg::CompiledRegistry,
    entity: &str,
    profile: &str,
    jurisdiction: &str,
) -> ClaimContext {
    ClaimContext::for_compiled(
        registry,
        entity,
        Some(PRINCIPAL.to_owned()),
        profile,
        Some("operations".to_owned()),
        vec![RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: jurisdiction.to_owned(),
        }],
    )
    .expect("claim context is compiler-bound")
}

async fn create_target(
    mutations: &MutationTransaction,
    client: &mut PooledClient,
    plan: &MutationPlan,
    claims: &ClaimContext,
    key: &str,
    name: &str,
) -> MutationOutcome {
    mutations
        .execute(
            client,
            create_request(
                plan,
                key,
                claims,
                Map::from_iter([
                    (
                        "jurisdiction".to_owned(),
                        Value::String("zone-a".to_owned()),
                    ),
                    ("name".to_owned(), Value::String(name.to_owned())),
                    ("related".to_owned(), Value::Null),
                ]),
                target_fields(),
            ),
        )
        .await
        .expect("target create commits")
}

#[allow(clippy::too_many_arguments)]
async fn patch_target(
    mutations: &MutationTransaction,
    client: &mut PooledClient,
    plan: &MutationPlan,
    claims: &ClaimContext,
    key: &str,
    record_id: &str,
    etag: &str,
    related: &str,
) -> Result<MutationOutcome, MutationError> {
    mutations
        .execute(
            client,
            MutationRequest {
                plan,
                idempotency_key: key,
                claims,
                record_id: Some(record_id),
                expected_etag: Some(etag),
                body: MutationBody::Patch(vec![PatchOperation::Replace {
                    path: "/data/related".to_owned(),
                    value: Value::String(related.to_owned()),
                }]),
                response_fields: target_fields(),
                representation: registry_breg::record_profile::RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
}

async fn create_source(
    mutations: &MutationTransaction,
    client: &mut PooledClient,
    plan: &MutationPlan,
    claims: &ClaimContext,
    key: &str,
    target: &str,
    alternate: Option<&str>,
) -> Result<MutationOutcome, MutationError> {
    mutations
        .execute(
            client,
            create_request(
                plan,
                key,
                claims,
                source_data(key, target, alternate),
                source_fields(),
            ),
        )
        .await
}

fn source_data(name: &str, target: &str, alternate: Option<&str>) -> Map<String, Value> {
    let mut data = Map::from_iter([
        (
            "jurisdiction".to_owned(),
            Value::String("zone-b".to_owned()),
        ),
        ("name".to_owned(), Value::String(name.to_owned())),
        ("target".to_owned(), Value::String(target.to_owned())),
        ("alternate".to_owned(), Value::Null),
    ]);
    if let Some(alternate) = alternate {
        data.insert("alternate".to_owned(), Value::String(alternate.to_owned()));
    }
    data
}

fn create_request<'a>(
    plan: &'a MutationPlan,
    key: &'a str,
    claims: &'a ClaimContext,
    data: Map<String, Value>,
    response_fields: BTreeSet<String>,
) -> MutationRequest<'a> {
    MutationRequest {
        plan,
        idempotency_key: key,
        claims,
        record_id: None,
        expected_etag: None,
        body: MutationBody::Create(data),
        response_fields,
        representation: registry_breg::record_profile::RecordRepresentation::Json,
        correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn patch(
    mutations: &MutationTransaction,
    client: &mut PooledClient,
    plan: &MutationPlan,
    claims: &ClaimContext,
    key: &str,
    record_id: &str,
    etag: &str,
    operations: Vec<PatchOperation>,
) -> Result<MutationOutcome, MutationError> {
    mutations
        .execute(
            client,
            MutationRequest {
                plan,
                idempotency_key: key,
                claims,
                record_id: Some(record_id),
                expected_etag: Some(etag),
                body: MutationBody::Patch(operations),
                response_fields: source_fields(),
                representation: registry_breg::record_profile::RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
}

#[allow(clippy::too_many_arguments)]
async fn tombstone(
    mutations: &MutationTransaction,
    client: &mut PooledClient,
    plan: &MutationPlan,
    claims: &ClaimContext,
    key: &str,
    record_id: &str,
    etag: &str,
    response_fields: &[&str],
) -> Result<MutationOutcome, MutationError> {
    mutations
        .execute(
            client,
            MutationRequest {
                plan,
                idempotency_key: key,
                claims,
                record_id: Some(record_id),
                expected_etag: Some(etag),
                body: MutationBody::Tombstone,
                response_fields: response_fields
                    .iter()
                    .map(|field| (*field).to_owned())
                    .collect(),
                representation: registry_breg::record_profile::RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
}

fn target_fields() -> BTreeSet<String> {
    ["jurisdiction", "name", "related"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn source_fields() -> BTreeSet<String> {
    ["jurisdiction", "name", "target", "alternate"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn response_id(outcome: &MutationOutcome) -> String {
    response_json(outcome)["data"]["recordIdentifier"]
        .as_str()
        .expect("response carries a record identifier")
        .to_owned()
}

fn response_revision(outcome: &MutationOutcome) -> i64 {
    response_json(outcome)["data"]["revisionIdentifier"]
        .as_str()
        .and_then(|revision| revision.parse().ok())
        .expect("response carries a record revision")
}

fn response_json(outcome: &MutationOutcome) -> Value {
    serde_json::from_slice(outcome.response().body()).expect("mutation response is JSON")
}

fn response_etag(outcome: &MutationOutcome) -> String {
    String::from_utf8(outcome.response().headers()[&PermittedResponseHeader::Etag].clone())
        .expect("response ETag is UTF-8")
}

async fn assert_source_hidden_from_target_profile(
    fixture: &Fixture,
    target_claims: &ClaimContext,
    source_id: &str,
) {
    let mut client = fixture
        .pool
        .get_for_test()
        .await
        .expect("visibility client");
    let transaction = begin_record_transaction(
        &mut client,
        RegistryLockKey::derive(PACKAGE_ID).expect("registry lock key is bounded"),
        Duration::from_secs(5),
        &fixture.identity,
        target_claims,
    )
    .await
    .expect("target caller starts a guarded transaction");
    let visible: i64 = transaction
        .transaction_for_test()
        .query_one(
            &format!(
                "SELECT count(*) FROM registry_data.{} WHERE record_id = $1",
                q(&fixture.registry.entities()["source"].physical_table)
            ),
            &[&Uuid::parse_str(source_id).expect("source id is a UUID")],
        )
        .await
        .expect("RLS-safe visibility probe succeeds")
        .get(0);
    assert_eq!(
        visible, 0,
        "the target caller cannot observe the source row"
    );
    transaction
        .rollback()
        .await
        .expect("visibility probe rolls back");
}

async fn assert_retained_reference(fixture: &Fixture, source_id: &str, target_id: &str) {
    assert_source_reference(fixture, source_id, "target", Some(target_id)).await;
    let snapshot: Vec<u8> = fixture
        .database
        .admin
        .query_one(
            "SELECT snapshot FROM registry_internal.registry_revisions
              WHERE entity_id = 'source' AND record_id = $1
              ORDER BY record_revision DESC LIMIT 1",
            &[&Uuid::parse_str(source_id).expect("source id is a UUID")],
        )
        .await
        .expect("administrator reads the tombstone revision")
        .get(0);
    let snapshot: Value = serde_json::from_slice(&snapshot).expect("revision snapshot is JSON");
    assert_eq!(snapshot["target"], target_id);
    assert_eq!(snapshot["alternate"], Value::Null);
}

async fn assert_source_reference(
    fixture: &Fixture,
    source_id: &str,
    field_id: &str,
    expected: Option<&str>,
) {
    let entity = &fixture.registry.entities()["source"];
    let value: Option<Uuid> = fixture
        .database
        .admin
        .query_one(
            &format!(
                "SELECT {} FROM registry_data.{} WHERE record_id = $1",
                q(&entity.fields[field_id].physical_name),
                q(&entity.physical_table)
            ),
            &[&Uuid::parse_str(source_id).expect("source id is a UUID")],
        )
        .await
        .expect("administrator reads retained reference storage")
        .get(0);
    assert_eq!(value.map(|value| value.to_string()).as_deref(), expected);
}

async fn assert_record(
    fixture: &Fixture,
    entity_id: &str,
    record_id: &str,
    lifecycle: &str,
    revision: i64,
) {
    let row = fixture
        .database
        .admin
        .query_one(
            &format!(
                "SELECT record_lifecycle, record_revision FROM registry_data.{}
                  WHERE record_id = $1",
                q(&fixture.registry.entities()[entity_id].physical_table)
            ),
            &[&Uuid::parse_str(record_id).expect("record id is a UUID")],
        )
        .await
        .expect("administrator reads final record state");
    assert_eq!(row.get::<_, String>(0), lifecycle);
    assert_eq!(row.get::<_, i64>(1), revision);
}

#[derive(Debug, Eq, PartialEq)]
struct DurableState {
    source_rows: i64,
    revisions: i64,
    idempotency: i64,
    outbox: i64,
    commits: i64,
    commit_members: i64,
}

async fn durable_state(fixture: &Fixture) -> DurableState {
    let row = fixture
        .database
        .admin
        .query_one(
            &format!(
                "SELECT
                   (SELECT count(*) FROM registry_data.{}),
                   (SELECT count(*) FROM registry_internal.registry_revisions),
                   (SELECT count(*) FROM registry_internal.registry_idempotency),
                   (SELECT count(*) FROM registry_internal.registry_outbox),
                   (SELECT count(*) FROM registry_internal.registry_revision_commits),
                   (SELECT count(*) FROM registry_internal.registry_revision_commit_members)",
                q(&fixture.registry.entities()["source"].physical_table)
            ),
            &[],
        )
        .await
        .expect("administrator reads durable effect counts");
    DurableState {
        source_rows: row.get(0),
        revisions: row.get(1),
        idempotency: row.get(2),
        outbox: row.get(3),
        commits: row.get(4),
        commit_members: row.get(5),
    }
}

async fn backend_pid(client: &Client) -> i32 {
    client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("backend pid is available")
        .get(0)
}

async fn assert_waits_for<F, T>(
    observer: &Client,
    blocked_pid: i32,
    blocker_pid: i32,
    operation: &mut std::pin::Pin<&mut F>,
    message: &str,
) where
    F: std::future::Future<Output = T>,
{
    let blocked = wait_until_blocked_by(observer, blocked_pid, blocker_pid);
    tokio::pin!(blocked);
    tokio::select! {
        _ = operation => panic!("{message}: operation completed before the barrier was observed"),
        () = &mut blocked => {}
    }
}

async fn wait_until_blocked_by(observer: &Client, blocked_pid: i32, blocker_pid: i32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            observer
                .query_one("SELECT pg_stat_clear_snapshot()", &[])
                .await
                .expect("observer refreshes the activity snapshot");
            let blocked: bool = observer
                .query_one(
                    "SELECT $1::integer = ANY(pg_blocking_pids($2::integer))",
                    &[&blocker_pid, &blocked_pid],
                )
                .await
                .expect("observer checks PostgreSQL blockers")
                .get(0);
            if blocked {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("operation reaches the intended PostgreSQL barrier");
}

fn assert_value_free_conflict(
    error: MutationError,
    registry: &registry_breg::CompiledRegistry,
    canaries: &[&str],
) {
    assert_eq!(error, MutationError::Conflict);
    assert_eq!(error.to_string(), "mutation conflicts with current state");
    let rendered = format!("{error:?} {error}");
    for canary in canaries.iter().copied().chain([PRINCIPAL]) {
        assert!(!rendered.contains(canary));
    }
    for entity in registry.entities().values() {
        assert!(!rendered.contains(&entity.physical_table));
        for field in entity.fields.values() {
            assert!(!rendered.contains(&field.physical_name));
        }
    }
}

fn q(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}
