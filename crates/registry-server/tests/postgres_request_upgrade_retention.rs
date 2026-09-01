// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::BTreeSet;
use std::env;

use postgres_harness::TestDatabase;
use registry_platform_audit::AuditProfile;
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    verify_catalog_identity_for_catalog, ExpectedManagedCatalog, RegistryLockKey,
    RegistryStateTestIdentity,
};
use registry_server::request_retention::{
    erase_request_detail, guard_successor_activation, load_retained_history,
    RequestDetailErasureScope, RequestRetentionError, RequestRetentionOperatorService,
    RetainedHistoryQuery,
};
use serde_json::json;
use tokio_postgres::Client;
use uuid::Uuid;

const REQUEST_ENTITY: &str = "placement-correction-request";
const REQUEST_ID: &str = "00000000-0000-0000-0000-00000000c001";
const TARGET_ID: &str = "00000000-0000-0000-0000-00000000c002";
const OLD_SITE_ID: &str = "00000000-0000-0000-0000-00000000c004";
const NEW_SITE_ID: &str = "00000000-0000-0000-0000-00000000c005";
const APPLICATION_ID: &str = "00000000-0000-0000-0000-00000000c003";
const CANCELED_REQUEST_ID: &str = "00000000-0000-0000-0000-00000000c011";
const ACTIVE_DRAFT_REQUEST_ID: &str = "00000000-0000-0000-0000-00000000c021";
const SECOND_RETENTION_LIST_REQUEST_ID: &str = "00000000-0000-0000-0000-00000000c099";
const EFFECT_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const TENANT: &str = "tenant-a";

#[tokio::test]
async fn active_request_upgrade_guard_allows_unrelated_changes_and_refuses_relevant_changes() {
    load_postgres_env();
    let base = compiled_registry(false, "internal");
    let unchanged_relevant = compiled_registry(true, "internal");
    let changed_relevant = compiled_registry(false, "restricted");
    let fingerprint = request_fingerprint(&base);

    let database = TestDatabase::create(1).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &base, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    seed_submitted_request(&migration, &fingerprint).await;

    guard_successor_activation(&migration, &unchanged_relevant)
        .await
        .expect("unrelated package changes preserve active request proposals");
    assert_eq!(
        guard_successor_activation(&migration, &changed_relevant).await,
        Err(RequestRetentionError::ActiveProposalRequiresRebase),
        "changed relevant request contract requires explicit rebase or cancellation"
    );

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn active_current_request_details_are_pinned_before_terminal_state() {
    load_postgres_env();
    let registry = compiled_registry(false, "internal");
    let database = TestDatabase::create(1).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("compiled schema installs");

    for (index, state) in ["draft", "needs_changes", "submitted", "approved"]
        .into_iter()
        .enumerate()
    {
        let request_id = Uuid::from_u128(0x0000000000000000000000000000d000 + index as u128);
        migration
            .execute(
                "INSERT INTO registry_internal.registry_request_state
                     (request_entity_id, request_id, owner_reference, state,
                      proposal_version, workflow_revision)
                 VALUES ($1, $2, 'owner-ref', $3, 1, 1)",
                &[&REQUEST_ENTITY, &request_id, &state],
            )
            .await
            .expect("active request state inserts");
        assert_eq!(
            erase_request_detail(
                &mut migration,
                &registry,
                RequestDetailErasureScope {
                    request_entity_id: REQUEST_ENTITY,
                    request_id,
                    proposal_version: 1,
                },
            )
            .await,
            Err(RequestRetentionError::ActiveDetailPinned),
            "current {state} detail remains pinned"
        );
    }

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn canceled_draft_without_proposal_erases_current_detail_and_bound_sidecars() {
    load_postgres_env();
    let registry = compiled_registry(false, "internal");
    let database = TestDatabase::create(1).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    seed_domain_rows(&migration, &registry).await;
    seed_canceled_draft_without_proposal(&migration, &registry).await;
    assert_eq!(retained_payload_counts(&migration).await, (0, 0, 4, 4, 4));

    let erased = erase_request_detail(
        &mut migration,
        &registry,
        RequestDetailErasureScope {
            request_entity_id: REQUEST_ENTITY,
            request_id: Uuid::parse_str(CANCELED_REQUEST_ID).expect("request id is a UUID"),
            proposal_version: 1,
        },
    )
    .await
    .expect("canceled draft with no proposal erases current detail");
    assert_eq!(erased.proposal_snapshots, 0);
    assert_eq!(erased.target_snapshots, 0);
    assert_eq!(erased.idempotency_results, 3);
    assert_eq!(erased.request_revision_snapshots, 3);
    assert_eq!(erased.outbox_payloads, 3);
    assert_eq!(erased.current_intake_rows, 1);
    assert_eq!(retained_payload_counts(&migration).await, (0, 0, 1, 1, 1));
    let current_detail = request_current_detail(
        &migration,
        &registry,
        Uuid::parse_str(CANCELED_REQUEST_ID).unwrap(),
    )
    .await;
    assert_eq!(current_detail.0, Some(TENANT.to_owned()));
    assert!(current_detail.1.is_none());
    assert!(current_detail.2.is_none());
    assert!(current_detail.3.is_none());
    assert!(request_state_detail_erased(&migration, CANCELED_REQUEST_ID).await);

    let repeated = erase_request_detail(
        &mut migration,
        &registry,
        RequestDetailErasureScope {
            request_entity_id: REQUEST_ENTITY,
            request_id: Uuid::parse_str(CANCELED_REQUEST_ID).expect("request id is a UUID"),
            proposal_version: 1,
        },
    )
    .await
    .expect("repeat canceled erasure is idempotent");
    assert_eq!(repeated.proposal_snapshots, 0);
    assert_eq!(repeated.target_snapshots, 0);
    assert_eq!(repeated.idempotency_results, 0);
    assert_eq!(repeated.request_revision_snapshots, 0);
    assert_eq!(repeated.outbox_payloads, 0);
    assert_eq!(repeated.current_intake_rows, 0);
    assert_eq!(retained_payload_counts(&migration).await, (0, 0, 1, 1, 1));

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn exact_request_retention_erases_all_bound_payload_copies_and_keeps_provenance_links() {
    load_postgres_env();
    let registry = compiled_registry(false, "internal");
    let fingerprint = request_fingerprint(&registry);
    let database = TestDatabase::create(1).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let catalog = ExpectedManagedCatalog::compiled(&registry);
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: "change-request-retention",
            environment: "local",
            instance_id: "change-request-retention-instance",
            database_id: "change-request-retention-database",
            package_revision: "package-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("retention catalog identity initializes");
    seed_domain_rows(&migration, &registry).await;
    seed_submitted_request(&migration, &fingerprint).await;
    seed_request_intake_and_revisions(&migration, &registry).await;
    seed_application_provenance_and_receipts(&migration).await;

    assert_eq!(
        erase_request_detail(
            &mut migration,
            &registry,
            RequestDetailErasureScope {
                request_entity_id: REQUEST_ENTITY,
                request_id: Uuid::parse_str(REQUEST_ID).expect("request id is a UUID"),
                proposal_version: 1,
            },
        )
        .await,
        Err(RequestRetentionError::ActiveDetailPinned),
        "submitted current proposal snapshots are still needed for review/application"
    );
    assert_eq!(retained_payload_counts(&migration).await, (1, 1, 5, 6, 6));

    migration
        .execute(
            "UPDATE registry_internal.registry_request_state
                SET state = 'applied', workflow_revision = workflow_revision + 1
              WHERE request_entity_id = $1 AND request_id = $2",
            &[&REQUEST_ENTITY, &Uuid::parse_str(REQUEST_ID).unwrap()],
        )
        .await
        .expect("test marks request terminal");
    let erased = erase_request_detail(
        &mut migration,
        &registry,
        RequestDetailErasureScope {
            request_entity_id: REQUEST_ENTITY,
            request_id: Uuid::parse_str(REQUEST_ID).expect("request id is a UUID"),
            proposal_version: 1,
        },
    )
    .await
    .expect("terminal request detail erases without replacement detail");
    assert_eq!(erased.proposal_snapshots, 1);
    assert_eq!(erased.target_snapshots, 1);
    assert_eq!(erased.idempotency_results, 3);
    assert_eq!(erased.request_revision_snapshots, 4);
    assert_eq!(erased.outbox_payloads, 4);
    assert_eq!(erased.current_intake_rows, 1);
    assert_eq!(retained_payload_counts(&migration).await, (0, 0, 2, 2, 2));
    let current_detail =
        request_current_detail(&migration, &registry, Uuid::parse_str(REQUEST_ID).unwrap()).await;
    assert_eq!(current_detail.0, Some(TENANT.to_owned()));
    assert!(current_detail.1.is_none());
    assert!(current_detail.2.is_none());
    assert!(current_detail.3.is_none());
    restore_row_level_security(&migration, &registry).await;
    verify_catalog_identity_for_catalog(
        &migration,
        &identity,
        &catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("request erasure preserves catalog identity");

    let second_erasure = erase_request_detail(
        &mut migration,
        &registry,
        RequestDetailErasureScope {
            request_entity_id: REQUEST_ENTITY,
            request_id: Uuid::parse_str(REQUEST_ID).expect("request id is a UUID"),
            proposal_version: 1,
        },
    )
    .await
    .expect("second erasure does not resurrect retained detail");
    assert_eq!(second_erasure.proposal_snapshots, 0);
    assert_eq!(second_erasure.target_snapshots, 0);
    assert_eq!(second_erasure.idempotency_results, 0);
    assert_eq!(second_erasure.request_revision_snapshots, 0);
    assert_eq!(second_erasure.outbox_payloads, 0);
    assert_eq!(second_erasure.current_intake_rows, 0);

    let replay_refused = migration
        .query_one(
            "SELECT response_body IS NULL
               FROM registry_internal.registry_idempotency
              WHERE key_reference = 'mixed-batch-key'",
            &[],
        )
        .await
        .expect("linked mixed batch receipt remains queryable")
        .get::<_, bool>(0);
    assert!(replay_refused, "mixed batch response bytes are erased");

    let cross_entity_still_retained = migration
        .query_one(
            "SELECT response_body IS NOT NULL
               FROM registry_internal.registry_idempotency
              WHERE key_reference = 'other-request-key'",
            &[],
        )
        .await
        .expect("cross-entity receipt remains queryable")
        .get::<_, bool>(0);
    assert!(
        cross_entity_still_retained,
        "same UUID under a different request entity is not erased"
    );

    let mut authorized_targets = BTreeSet::new();
    authorized_targets.insert("placement".to_owned());
    let page = load_retained_history(
        &migration,
        RetainedHistoryQuery {
            request_entity_id: REQUEST_ENTITY,
            request_id: Uuid::parse_str(REQUEST_ID).unwrap(),
            after_proposal_version: None,
            limit: 1,
            authorized_target_entities: &authorized_targets,
        },
    )
    .await
    .expect("retained history loads without payload");
    assert_eq!(page.next_after_proposal_version, None);
    assert_eq!(page.proposals.len(), 1);
    let proposal = &page.proposals[0];
    assert!(proposal.detail_erased);
    assert_eq!(proposal.request_id, REQUEST_ID);
    assert_eq!(proposal.proposal_version, 1);
    assert_eq!(proposal.contract_fingerprint, fingerprint);
    assert_eq!(proposal.effect_digest, EFFECT_DIGEST);
    assert_eq!(proposal.application_id.as_deref(), Some(APPLICATION_ID));
    assert_eq!(proposal.result_link_count, 0);
    assert!(
        proposal.result_links.is_empty(),
        "retained history omits target IDs until exact row authority is proven"
    );

    let hidden_page = load_retained_history(
        &migration,
        RetainedHistoryQuery {
            request_entity_id: REQUEST_ENTITY,
            request_id: Uuid::parse_str(REQUEST_ID).unwrap(),
            after_proposal_version: None,
            limit: 1,
            authorized_target_entities: &BTreeSet::new(),
        },
    )
    .await
    .expect("unauthorized result identifiers are withheld");
    assert_eq!(hidden_page.proposals[0].result_link_count, 0);
    assert!(hidden_page.proposals[0].result_links.is_empty());

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn operator_retention_service_counts_pages_erases_under_forced_rls_and_audits() {
    load_postgres_env();
    let registry = compiled_registry(false, "internal");
    let fingerprint = request_fingerprint(&registry);
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    let catalog = ExpectedManagedCatalog::compiled(&registry);
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: "change-request-retention",
            environment: "local",
            instance_id: "change-request-retention-instance",
            database_id: "change-request-retention-database",
            package_revision: "package-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("retention catalog identity initializes");
    seed_domain_rows(&migration, &registry).await;
    seed_submitted_request(&migration, &fingerprint).await;
    seed_request_intake_and_revisions(&migration, &registry).await;
    seed_application_provenance_and_receipts(&migration).await;
    seed_second_retention_list_row(&migration, &fingerprint).await;
    seed_active_draft_without_proposal(&migration).await;
    restore_row_level_security(&migration, &registry).await;

    let audit = AuditProfile::production_from_secret_bytes(vec![0x51; 32].into())
        .expect("test audit profile is keyed");
    let service = RequestRetentionOperatorService::new_for_test(
        registry.clone(),
        identity.clone(),
        catalog,
        RegistryLockKey::derive(&identity.package_id).expect("registry lock key derives"),
        database.migration_config.clone(),
        database.migration_role.clone(),
        database.runtime_role.clone(),
        audit,
    );
    let scope = RequestDetailErasureScope {
        request_entity_id: REQUEST_ENTITY,
        request_id: Uuid::parse_str(REQUEST_ID).expect("request id is a UUID"),
        proposal_version: 1,
    };

    let active = service
        .dry_run(scope.clone())
        .await
        .expect("dry-run reports pinned request");
    assert!(active.pinned);
    assert!(!active.eligible_for_erasure);
    assert_eq!(active.retention_mode, "operator_erase");
    assert_eq!(active.erasure.proposal_snapshots, 1);

    let active_without_proposal = service
        .dry_run(RequestDetailErasureScope {
            request_entity_id: REQUEST_ENTITY,
            request_id: Uuid::parse_str(ACTIVE_DRAFT_REQUEST_ID).expect("request id is a UUID"),
            proposal_version: 1,
        })
        .await
        .expect("active draft without historical proposal remains inspectable");
    assert!(active_without_proposal.pinned);
    assert!(!active_without_proposal.eligible_for_erasure);
    assert_eq!(active_without_proposal.erasure.proposal_snapshots, 0);
    assert_eq!(active_without_proposal.erasure.current_intake_rows, 0);

    migration
        .execute(
            "UPDATE registry_internal.registry_request_state
                SET state = 'applied', workflow_revision = workflow_revision + 1
              WHERE request_entity_id = $1 AND request_id = $2",
            &[&REQUEST_ENTITY, &Uuid::parse_str(REQUEST_ID).unwrap()],
        )
        .await
        .expect("test marks request terminal");
    let first_page = service
        .list(Some(REQUEST_ENTITY), None, 1)
        .await
        .expect("first retention page loads");
    assert_eq!(first_page.requests.len(), 1);
    let cursor = first_page
        .next_cursor
        .as_deref()
        .expect("bounded list returns cursor");
    let second_page = service
        .list(Some(REQUEST_ENTITY), Some(cursor), 1)
        .await
        .expect("second retention page loads");
    assert_eq!(
        second_page.requests[0].request_id, ACTIVE_DRAFT_REQUEST_ID,
        "cursor resumes after the last returned row without skipping the omitted active request"
    );
    assert!(second_page.requests[0].pinned);

    let planned = service
        .dry_run(scope.clone())
        .await
        .expect("terminal dry-run succeeds");
    assert!(!planned.pinned);
    assert!(planned.eligible_for_erasure);
    assert_eq!(planned.erasure.proposal_snapshots, 1);
    assert_eq!(planned.erasure.target_snapshots, 1);
    assert_eq!(planned.erasure.idempotency_results, 3);
    assert_eq!(planned.erasure.request_revision_snapshots, 4);
    assert_eq!(planned.erasure.outbox_payloads, 4);
    assert_eq!(planned.erasure.current_intake_rows, 1);

    let before_history = history_commit_counts(&migration).await;
    let erased = service
        .erase(scope)
        .await
        .expect("operator erasure succeeds");
    assert_eq!(erased.erasure, planned.erasure);
    let after_history = history_commit_counts(&migration).await;
    assert_eq!(
        after_history.commits - before_history.commits,
        1,
        "operator erasure allocates one history commit for the current request tombstone"
    );
    assert_eq!(
        after_history.members - before_history.members,
        1,
        "operator erasure commit includes only the current request tombstone revision"
    );
    let request_id = Uuid::parse_str(REQUEST_ID).expect("request id parses");
    let current_request_revision =
        current_request_revision(&database.admin, &registry, request_id).await;
    let retention_members = retention_erasure_history_members(&migration, request_id).await;
    assert_eq!(
        retention_members,
        vec![HistoryCommitMember {
            entity_id: REQUEST_ENTITY.to_owned(),
            record_id: request_id,
            record_revision: current_request_revision,
        }],
        "operator erasure commit member points at the tombstoned request revision"
    );
    assert_eq!(retained_payload_counts(&migration).await, (0, 0, 2, 2, 2));
    assert!(
        request_table_force_rls(&migration, &registry).await,
        "operator erasure restores FORCE ROW LEVEL SECURITY"
    );
    let audit_rows = migration
        .query_one("SELECT count(*) FROM registry_internal.registry_audit", &[])
        .await
        .expect("audit table remains readable")
        .get::<_, i64>(0);
    assert_eq!(
        audit_rows, 1,
        "operator erasure appends one durable audit record"
    );

    migration_task.abort();
    database.cleanup().await;
}

async fn seed_active_draft_without_proposal(client: &Client) {
    let request_id = Uuid::parse_str(ACTIVE_DRAFT_REQUEST_ID).expect("request id parses");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_state
                 (request_entity_id, request_id, owner_reference, state,
                  proposal_version, workflow_revision)
             VALUES ($1, $2, 'owner-ref', 'draft', 1, 1)",
            &[&REQUEST_ENTITY, &request_id],
        )
        .await
        .expect("active draft request state inserts");
}

async fn seed_canceled_draft_without_proposal(
    client: &Client,
    registry: &registry_server::CompiledRegistry,
) {
    client
        .execute(
            "SELECT set_config('registry.active_package_revision', 'package-1', false)",
            &[],
        )
        .await
        .expect("active package revision is set");
    let request = &registry.entities()[REQUEST_ENTITY];
    client
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{} NO FORCE ROW LEVEL SECURITY",
            quote(&request.physical_table)
        ))
        .await
        .expect("test can seed request table");
    let tenant = &request.fields["tenant"].physical_name;
    let placement = &request.fields["placement"].physical_name;
    let proposed_site = &request.fields["proposed-site"].physical_name;
    let reason = &request.fields["reason"].physical_name;
    let request_id = Uuid::parse_str(CANCELED_REQUEST_ID).expect("request id parses");
    client
        .execute(
            &format!(
                "INSERT INTO registry_data.{} (record_id, record_revision, record_lifecycle, active_package_revision, {}, {}, {}, {})
                 VALUES ($1, 3, 'active', 'package-1', $2, $3, $4, 'canceled draft detail')",
                quote(&request.physical_table),
                quote(tenant),
                quote(placement),
                quote(proposed_site),
                quote(reason)
            ),
            &[
                &request_id,
                &TENANT,
                &Uuid::parse_str(TARGET_ID).unwrap(),
                &Uuid::parse_str(NEW_SITE_ID).unwrap(),
            ],
        )
        .await
        .expect("canceled draft request row inserts");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_state
                 (request_entity_id, request_id, owner_reference, state,
                  proposal_version, workflow_revision)
             VALUES ($1, $2, 'owner-ref', 'canceled', 1, 4),
                    ('other-request-entity', $2, 'other-owner', 'canceled', 1, 4)",
            &[&REQUEST_ENTITY, &request_id],
        )
        .await
        .expect("canceled request state inserts");
    client
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision,
                  operation_id, mutation_kind, principal_reference, request_reference, snapshot)
             VALUES ($1, $2, 'canceled-request-ref', 1, NULL, 'active', 'package-1',
                     'records.create', 'create', 'principal-ref', 'create-ref',
                     convert_to('{\"reason\":\"created canceled draft\"}', 'UTF8')),
                    ($1, $2, 'canceled-request-ref', 2, 1, 'active', 'package-1',
                     'records.patch', 'patch', 'principal-ref', 'draft-patch-ref',
                     convert_to('{\"reason\":\"patched canceled draft\"}', 'UTF8')),
                    ($1, $2, 'canceled-request-ref', 3, 2, 'active', 'package-1',
                     'records.request.cancel', 'patch', 'principal-ref', 'cancel-ref',
                     convert_to('{\"reason\":\"canceled detail\"}', 'UTF8')),
                    ('other-request-entity', $2, 'other-canceled-request-ref', 1, NULL,
                     'active', 'package-1', 'records.create', 'create', 'principal-ref',
                     'other-ref', convert_to('{\"reason\":\"other entity detail\"}', 'UTF8'))",
            &[&REQUEST_ENTITY, &request_id],
        )
        .await
        .expect("canceled request revision snapshots insert");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_revision_links
                 (entity_id, record_id, record_revision, request_entity_id, request_id,
                  proposal_version, link_kind)
             VALUES ($1, $2, 1, $1, $2, 1, 'request_create'),
                    ($1, $2, 2, $1, $2, 1, 'request_patch'),
                    ($1, $2, 3, $1, $2, 1, 'request_lifecycle'),
                    ('other-request-entity', $2, 1, 'other-request-entity', $2, 1,
                     'request_create')",
            &[&REQUEST_ENTITY, &request_id],
        )
        .await
        .expect("canceled request revision links insert");
    client
        .batch_execute(
            "INSERT INTO registry_internal.registry_outbox
                 (event_id, event_type, trigger, entity_id, record_reference,
                  record_revision, package_revision, schema_fingerprint, payload,
                  payload_expires_at)
             VALUES ('00000000-0000-0000-0000-000000001101'::uuid,
                     'canceled-request-created', 'created', 'placement-correction-request',
                     'canceled-request-ref', 1, 'package-1', 'schema-1',
                     convert_to('{\"reason\":\"created canceled draft\"}', 'UTF8'),
                     transaction_timestamp() + interval '1 day'),
                    ('00000000-0000-0000-0000-000000001102'::uuid,
                     'canceled-request-patched', 'patched', 'placement-correction-request',
                     'canceled-request-ref', 2, 'package-1', 'schema-1',
                     convert_to('{\"reason\":\"patched canceled draft\"}', 'UTF8'),
                     transaction_timestamp() + interval '1 day'),
                    ('00000000-0000-0000-0000-000000001103'::uuid,
                     'canceled-request-canceled', 'request_lifecycle',
                     'placement-correction-request', 'canceled-request-ref', 3,
                     'package-1', 'schema-1',
                     convert_to('{\"reason\":\"canceled detail\"}', 'UTF8'),
                     transaction_timestamp() + interval '1 day'),
                    ('00000000-0000-0000-0000-000000001104'::uuid,
                     'other-canceled-request-created', 'created', 'other-request-entity',
                     'other-canceled-request-ref', 1, 'package-1', 'schema-1',
                     convert_to('{\"reason\":\"other entity detail\"}', 'UTF8'),
                     transaction_timestamp() + interval '1 day')",
        )
        .await
        .expect("canceled request outbox payload copies insert");
    client
        .execute(
            "INSERT INTO registry_internal.registry_idempotency
                 (key_reference, binding_reference, result_kind, record_reference,
                  record_revision, result_count, proposal_version, response_status,
                  response_body, response_headers)
             VALUES ('canceled-create-key', 'canceled-create-binding', 'record',
                     'canceled-request-ref', 1, NULL, NULL, 201,
                     convert_to('{\"id\":\"created canceled draft\"}', 'UTF8'), decode('0000', 'hex')),
                    ('canceled-patch-key', 'canceled-patch-binding', 'record',
                     'canceled-request-ref', 2, NULL, NULL, 200,
                     convert_to('{\"id\":\"patched canceled draft\"}', 'UTF8'), decode('0000', 'hex')),
                    ('canceled-batch-key', 'canceled-batch-binding', 'batch',
                     NULL, NULL, 2, NULL, 200,
                     convert_to('{\"results\":[{},{}]}', 'UTF8'), decode('0000', 'hex')),
                    ('other-canceled-key', 'other-canceled-binding', 'record',
                     'other-canceled-request-ref', 1, NULL, NULL, 200,
                     convert_to('{\"id\":\"other entity detail\"}', 'UTF8'), decode('0000', 'hex'))",
            &[],
        )
        .await
        .expect("canceled request idempotency rows insert");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_idempotency_links
                 (key_reference, request_entity_id, request_id, proposal_version)
             VALUES ('canceled-create-key', $1, $2, 1),
                    ('canceled-patch-key', $1, $2, 1),
                    ('canceled-batch-key', $1, $2, 1),
                    ('canceled-batch-key', 'other-request-entity', $2, 1),
                    ('other-canceled-key', 'other-request-entity', $2, 1)",
            &[&REQUEST_ENTITY, &request_id],
        )
        .await
        .expect("canceled request idempotency links insert");
}

async fn request_state_detail_erased(client: &Client, request_id: &str) -> bool {
    client
        .query_one(
            "SELECT detail_erased_at IS NOT NULL
               FROM registry_internal.registry_request_state
              WHERE request_entity_id = $1 AND request_id = $2",
            &[&REQUEST_ENTITY, &Uuid::parse_str(request_id).unwrap()],
        )
        .await
        .expect("request state detail erasure marker loads")
        .get(0)
}

async fn seed_submitted_request(client: &Client, contract_fingerprint: &str) {
    let request_id = Uuid::parse_str(REQUEST_ID).expect("request id parses");
    let target_id = Uuid::parse_str(TARGET_ID).expect("target id parses");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_state
                 (request_entity_id, request_id, owner_reference, state,
                  proposal_version, workflow_revision)
             VALUES ($1, $2, 'owner-ref', 'submitted', 1, 2)",
            &[&REQUEST_ENTITY, &request_id],
        )
        .await
        .expect("request state inserts");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_proposals
                 (request_entity_id, request_id, proposal_version,
                  request_record_revision, contract_fingerprint, effect_digest, snapshot)
             VALUES ($1, $2, 1, 7, $3, $4, $5::jsonb)",
            &[
                &REQUEST_ENTITY,
                &request_id,
                &contract_fingerprint,
                &EFFECT_DIGEST,
                &json!({"effects": [{"id": "patch-placement"}]}),
            ],
        )
        .await
        .expect("proposal snapshot inserts");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_targets
                 (request_entity_id, request_id, proposal_version, target_entity_id,
                  target_record_id, operation, expected_revision, base_snapshot, after_snapshot)
             VALUES ($1, $2, 1, 'placement', $3, 'patch', 1,
                     $4::jsonb, $5::jsonb)",
            &[
                &REQUEST_ENTITY,
                &request_id,
                &target_id,
                &json!({"site": OLD_SITE_ID}),
                &json!({"site": NEW_SITE_ID}),
            ],
        )
        .await
        .expect("target snapshots insert");
}

async fn seed_second_retention_list_row(client: &Client, contract_fingerprint: &str) {
    let request_id = Uuid::parse_str(SECOND_RETENTION_LIST_REQUEST_ID).expect("request id parses");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_state
                 (request_entity_id, request_id, owner_reference, state,
                  proposal_version, workflow_revision, detail_erased_at)
             VALUES ($1, $2, 'owner-ref', 'canceled', 1, 2, transaction_timestamp())",
            &[&REQUEST_ENTITY, &request_id],
        )
        .await
        .expect("second request state inserts");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_proposals
                 (request_entity_id, request_id, proposal_version,
                  request_record_revision, contract_fingerprint, effect_digest, snapshot, erased_at)
             VALUES ($1, $2, 1, 1, $3, $4, NULL, transaction_timestamp())",
            &[
                &REQUEST_ENTITY,
                &request_id,
                &contract_fingerprint,
                &EFFECT_DIGEST,
            ],
        )
        .await
        .expect("second proposal stub inserts");
}

async fn restore_row_level_security(client: &Client, registry: &registry_server::CompiledRegistry) {
    for entity in registry.entities().values() {
        client
            .batch_execute(&format!(
                "ALTER TABLE registry_data.{} FORCE ROW LEVEL SECURITY",
                quote(&entity.physical_table)
            ))
            .await
            .expect("test restores compiled data table row security");
    }
}

async fn request_table_force_rls(
    client: &Client,
    registry: &registry_server::CompiledRegistry,
) -> bool {
    let request = &registry.entities()[REQUEST_ENTITY];
    client
        .query_one(
            "SELECT relforcerowsecurity
               FROM pg_catalog.pg_class
              WHERE oid = format('registry_data.%I', $1::text)::regclass",
            &[&request.physical_table],
        )
        .await
        .expect("request table row-security state loads")
        .get(0)
}

async fn seed_domain_rows(client: &Client, registry: &registry_server::CompiledRegistry) {
    client
        .execute(
            "SELECT set_config('registry.active_package_revision', 'package-1', false)",
            &[],
        )
        .await
        .expect("active package revision is set");
    for entity in registry.entities().values() {
        client
            .batch_execute(&format!(
                "ALTER TABLE registry_data.{} NO FORCE ROW LEVEL SECURITY",
                quote(&entity.physical_table)
            ))
            .await
            .expect("test can seed compiled data tables");
    }
    let site = &registry.entities()["site"];
    let site_label = &site.fields["label"].physical_name;
    client
        .execute(
            &format!(
                "INSERT INTO registry_data.{} (record_id, record_revision, record_lifecycle, active_package_revision, {})
                 VALUES ($1, 1, 'active', 'package-1', 'old'),
                        ($2, 1, 'active', 'package-1', 'new')",
                quote(&site.physical_table),
                quote(site_label)
            ),
            &[
                &Uuid::parse_str(OLD_SITE_ID).unwrap(),
                &Uuid::parse_str(NEW_SITE_ID).unwrap(),
            ],
        )
        .await
        .expect("site rows insert");
    let placement = &registry.entities()["placement"];
    let placement_site = &placement.fields["site"].physical_name;
    let placement_label = &placement.fields["label"].physical_name;
    client
        .execute(
            &format!(
                "INSERT INTO registry_data.{} (record_id, record_revision, record_lifecycle, active_package_revision, {}, {})
                 VALUES ($1, 1, 'active', 'package-1', $2, 'target')",
                quote(&placement.physical_table),
                quote(placement_site),
                quote(placement_label)
            ),
            &[
                &Uuid::parse_str(TARGET_ID).unwrap(),
                &Uuid::parse_str(OLD_SITE_ID).unwrap(),
            ],
        )
        .await
        .expect("placement row inserts");
}

async fn seed_request_intake_and_revisions(
    client: &Client,
    registry: &registry_server::CompiledRegistry,
) {
    let request = &registry.entities()[REQUEST_ENTITY];
    let tenant = &request.fields["tenant"].physical_name;
    let placement = &request.fields["placement"].physical_name;
    let proposed_site = &request.fields["proposed-site"].physical_name;
    let reason = &request.fields["reason"].physical_name;
    client
        .execute(
            &format!(
                "INSERT INTO registry_data.{} (record_id, record_revision, record_lifecycle, active_package_revision, {}, {}, {}, {})
                 VALUES ($1, 8, 'active', 'package-1', $2, $3, $4, 'original reason')",
                quote(&request.physical_table),
                quote(tenant),
                quote(placement),
                quote(proposed_site),
                quote(reason)
            ),
            &[
                &Uuid::parse_str(REQUEST_ID).unwrap(),
                &TENANT,
                &Uuid::parse_str(TARGET_ID).unwrap(),
                &Uuid::parse_str(NEW_SITE_ID).unwrap(),
            ],
        )
        .await
        .expect("request current row inserts");
    let request_id = Uuid::parse_str(REQUEST_ID).unwrap();
    client
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision,
                  operation_id, mutation_kind, principal_reference, request_reference, snapshot)
             VALUES ($1, $2, 'request-ref', 5, NULL, 'active', 'package-1',
                     'records.create', 'create', 'principal-ref', 'create-ref',
                     convert_to('{\"reason\":\"created detail\"}', 'UTF8')),
                    ($1, $2, 'request-ref', 6, 5, 'active', 'package-1',
                     'records.patch', 'patch', 'principal-ref', 'draft-patch-ref',
                     convert_to('{\"reason\":\"draft detail\"}', 'UTF8')),
                    ($1, $2, 'request-ref', 7, 6, 'active', 'package-1',
                     'records.request.submit', 'patch', 'principal-ref', 'request-action-ref',
                     convert_to('{\"reason\":\"original reason\"}', 'UTF8')),
                    ($1, $2, 'request-ref', 8, 7, 'active', 'package-1',
                     'records.request.approve', 'patch', 'principal-ref', 'request-action-ref',
                     convert_to('{\"reason\":\"approved detail\"}', 'UTF8')),
                    ('other-request-entity', $2, 'other-request-ref', 1, NULL, 'active',
                     'package-1', 'records.create', 'create', 'principal-ref', 'other-ref',
                     convert_to('{\"reason\":\"same uuid other entity\"}', 'UTF8'))",
            &[&REQUEST_ENTITY, &request_id],
        )
        .await
        .expect("request revision snapshots insert");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_state
                 (request_entity_id, request_id, owner_reference, state,
                  proposal_version, workflow_revision)
             VALUES ('other-request-entity', $1, 'other-owner', 'draft', 1, 1)",
            &[&request_id],
        )
        .await
        .expect("same UUID under another request entity inserts");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_revision_links
                 (entity_id, record_id, record_revision, request_entity_id, request_id,
                  proposal_version, link_kind)
             VALUES ($1, $2, 5, $1, $2, 1, 'request_create'),
                    ($1, $2, 6, $1, $2, 1, 'request_patch'),
                    ($1, $2, 7, $1, $2, 1, 'request_lifecycle'),
                    ($1, $2, 8, $1, $2, 1, 'request_lifecycle'),
                    ('other-request-entity', $2, 1, 'other-request-entity', $2, 1,
                     'request_create')",
            &[&REQUEST_ENTITY, &request_id],
        )
        .await
        .expect("request revision links insert");
    client
        .batch_execute(
            "INSERT INTO registry_internal.registry_outbox
                 (event_id, event_type, trigger, entity_id, record_reference,
                  record_revision, package_revision, schema_fingerprint, payload,
                  payload_expires_at)
             VALUES ('00000000-0000-0000-0000-000000001005'::uuid,
                     'request-created', 'created', 'placement-correction-request',
                     'request-ref', 5, 'package-1', 'schema-1',
                     convert_to('{\"reason\":\"created detail\"}', 'UTF8'),
                     transaction_timestamp() + interval '1 day'),
                    ('00000000-0000-0000-0000-000000001006'::uuid,
                     'request-patched', 'patched', 'placement-correction-request',
                     'request-ref', 6, 'package-1', 'schema-1',
                     convert_to('{\"reason\":\"draft detail\"}', 'UTF8'),
                     transaction_timestamp() + interval '1 day'),
                    ('00000000-0000-0000-0000-000000001007'::uuid,
                     'request-submitted', 'request_lifecycle', 'placement-correction-request',
                     'request-ref', 7, 'package-1', 'schema-1',
                     convert_to('{\"reason\":\"submit detail\"}', 'UTF8'),
                     transaction_timestamp() + interval '1 day'),
                    ('00000000-0000-0000-0000-000000001008'::uuid,
                     'request-approved', 'request_lifecycle', 'placement-correction-request',
                     'request-ref', 8, 'package-1', 'schema-1',
                     convert_to('{\"reason\":\"approve detail\"}', 'UTF8'),
                     transaction_timestamp() + interval '1 day'),
                    ('00000000-0000-0000-0000-000000001009'::uuid,
                     'other-request-created', 'created', 'other-request-entity',
                     'other-request-ref', 1, 'package-1', 'schema-1',
                     convert_to('{\"reason\":\"other entity\"}', 'UTF8'),
                     transaction_timestamp() + interval '1 day'),
                    ('00000000-0000-0000-0000-000000001010'::uuid,
                     'ordinary-created', 'created', 'placement-correction-request',
                     'ordinary-ref', 99, 'package-1', 'schema-1',
                     convert_to('{\"reason\":\"unlinked\"}', 'UTF8'),
                     transaction_timestamp() + interval '1 day')",
        )
        .await
        .expect("request outbox payload copies insert");
}

async fn seed_application_provenance_and_receipts(client: &Client) {
    let request_id = Uuid::parse_str(REQUEST_ID).expect("request id parses");
    let target_id = Uuid::parse_str(TARGET_ID).expect("target id parses");
    let application_id = Uuid::parse_str(APPLICATION_ID).expect("application id parses");
    client
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision,
                  operation_id, mutation_kind, principal_reference, request_reference, snapshot)
             VALUES ('placement', $1, 'target-ref', 2, 1, 'active', 'package-1',
                     'records.request.apply', 'patch', 'principal-ref', 'request-ref',
                     convert_to('{\"site\":\"new\"}', 'UTF8'))",
            &[&target_id],
        )
        .await
        .expect("target revision provenance inserts");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_applications
                 (request_entity_id, request_id, proposal_version, application_id,
                  effect_digest, applied_by, applied_at)
             VALUES ($1, $2, 1, $3, $4, 'operator-ref', transaction_timestamp())",
            &[
                &REQUEST_ENTITY,
                &request_id,
                &application_id,
                &EFFECT_DIGEST,
            ],
        )
        .await
        .expect("application provenance inserts");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_results
                 (request_entity_id, request_id, proposal_version, target_entity_id,
                  target_record_id, target_revision)
             VALUES ($1, $2, 1, 'placement', $3, 2)",
            &[&REQUEST_ENTITY, &request_id, &target_id],
        )
        .await
        .expect("result link inserts");
    client
        .execute(
            "INSERT INTO registry_internal.registry_idempotency
                 (key_reference, binding_reference, result_kind, record_reference,
                  record_revision, result_count, proposal_version, response_status,
                  response_body, response_headers)
             VALUES ('submit-key', 'submit-binding', 'record', 'request-record-ref', 7, NULL,
                     NULL, 200, convert_to('{\"id\":\"request-action\"}', 'UTF8'), decode('0000', 'hex')),
                    ('application-key', 'application-binding', 'application',
                     'request-record-ref', 8, 1, 1, 200,
                     convert_to('{\"id\":\"application\"}', 'UTF8'), decode('0000', 'hex')),
                    ('mixed-batch-key', 'mixed-batch-binding', 'batch', NULL, NULL, 2,
                     NULL, 200, convert_to('{\"results\":[{},{}]}', 'UTF8'), decode('0000', 'hex')),
                    ('other-request-key', 'other-binding', 'record', 'other-record-ref', 4, NULL,
                     NULL, 200,
                     convert_to('{\"id\":\"same-uuid-other-entity\"}', 'UTF8'), decode('0000', 'hex')),
                    ('ordinary-key', 'ordinary-binding', 'record', 'ordinary-ref', 5, NULL,
                     NULL, 200,
                     convert_to('{\"id\":\"same-json-shape\"}', 'UTF8'), decode('0000', 'hex'))",
            &[],
        )
        .await
        .expect("request and unrelated idempotency results insert");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_idempotency_links
                 (key_reference, request_entity_id, request_id, proposal_version)
             VALUES ('submit-key', $1, $2, 1),
                    ('application-key', $1, $2, 1),
                    ('mixed-batch-key', $1, $2, 1),
                    ('mixed-batch-key', 'other-request-entity', $2, 1),
                    ('other-request-key', 'other-request-entity', $2, 1)",
            &[&REQUEST_ENTITY, &request_id],
        )
        .await
        .expect("request idempotency links insert");
}

async fn retained_payload_counts(client: &Client) -> (i64, i64, i64, i64, i64) {
    let row = client
        .query_one(
            "SELECT
                (SELECT count(*) FROM registry_internal.registry_request_proposals
                  WHERE snapshot IS NOT NULL),
                (SELECT count(*) FROM registry_internal.registry_request_targets
                  WHERE base_snapshot IS NOT NULL OR after_snapshot IS NOT NULL),
                (SELECT count(*) FROM registry_internal.registry_idempotency
                  WHERE response_body IS NOT NULL),
                (SELECT count(*) FROM registry_internal.registry_revisions
                  WHERE snapshot IS NOT NULL),
                (SELECT count(*) FROM registry_internal.registry_outbox
                  WHERE payload IS NOT NULL)",
            &[],
        )
        .await
        .expect("payload count query succeeds");
    (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))
}

#[derive(Debug, Eq, PartialEq)]
struct HistoryCommitCounts {
    commits: i64,
    members: i64,
}

async fn history_commit_counts(client: &Client) -> HistoryCommitCounts {
    let row = client
        .query_one(
            "SELECT
                 (SELECT count(*) FROM registry_internal.registry_revision_commits),
                 (SELECT count(*) FROM registry_internal.registry_revision_commit_members)",
            &[],
        )
        .await
        .expect("administrator can inspect history commits");
    HistoryCommitCounts {
        commits: row.get(0),
        members: row.get(1),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct HistoryCommitMember {
    entity_id: String,
    record_id: Uuid,
    record_revision: i64,
}

async fn retention_erasure_history_members(
    client: &Client,
    request_id: Uuid,
) -> Vec<HistoryCommitMember> {
    client
        .query(
            "SELECT member.entity_id, member.record_id, member.record_revision
               FROM registry_internal.registry_revision_commits AS revision_commit
               JOIN registry_internal.registry_revision_commit_members AS member
                 ON member.commit_position = revision_commit.commit_position
              WHERE revision_commit.origin_kind = 'migration'
                AND revision_commit.system_origin = 'registry-server-request-retention-erasure-v1'
                AND revision_commit.migration_reference = 'records.request.retention.erase'
                AND member.entity_id = $1
                AND member.record_id = $2
              ORDER BY member.member_index",
            &[&REQUEST_ENTITY, &request_id],
        )
        .await
        .expect("administrator can inspect retention history commit members")
        .into_iter()
        .map(|row| HistoryCommitMember {
            entity_id: row.get(0),
            record_id: row.get(1),
            record_revision: row.get(2),
        })
        .collect()
}

async fn current_request_revision(
    client: &Client,
    registry: &registry_server::CompiledRegistry,
    request_id: Uuid,
) -> i64 {
    let request = &registry.entities()[REQUEST_ENTITY];
    client
        .query_one(
            &format!(
                "SELECT record_revision
                   FROM registry_data.{}
                  WHERE record_id = $1",
                quote(&request.physical_table)
            ),
            &[&request_id],
        )
        .await
        .expect("current request revision loads")
        .get(0)
}

async fn request_current_detail(
    client: &Client,
    registry: &registry_server::CompiledRegistry,
    request_id: Uuid,
) -> (Option<String>, Option<Uuid>, Option<Uuid>, Option<String>) {
    let request = &registry.entities()[REQUEST_ENTITY];
    let tenant = &request.fields["tenant"].physical_name;
    let placement = &request.fields["placement"].physical_name;
    let proposed_site = &request.fields["proposed-site"].physical_name;
    let reason = &request.fields["reason"].physical_name;
    client
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{} NO FORCE ROW LEVEL SECURITY",
            quote(&request.physical_table)
        ))
        .await
        .expect("test inspection can read request table");
    let row = client
        .query_one(
            &format!(
                "SELECT {}, {}, {}, {} FROM registry_data.{} WHERE record_id = $1",
                quote(tenant),
                quote(placement),
                quote(proposed_site),
                quote(reason),
                quote(&request.physical_table)
            ),
            &[&request_id],
        )
        .await
        .expect("request current detail loads");
    client
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{} FORCE ROW LEVEL SECURITY",
            quote(&request.physical_table)
        ))
        .await
        .expect("test inspection restores request table FORCE RLS");
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

fn compiled_registry(
    include_extra_entity: bool,
    request_reason_classification: &str,
) -> registry_server::CompiledRegistry {
    let project = parse_project_json(&change_request_project(
        include_extra_entity,
        request_reason_classification,
    ))
    .expect("project parses");
    compile_project(&project, &[], CompileProfile::Authoring).expect("project compiles")
}

fn request_fingerprint(registry: &registry_server::CompiledRegistry) -> String {
    registry.entities()[REQUEST_ENTITY]
        .change_request
        .as_ref()
        .expect("request plan is compiled")
        .contract_fingerprint
        .clone()
}

fn quote(identifier: &str) -> String {
    assert!(identifier
        .bytes()
        .all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit()));
    format!("\"{identifier}\"")
}

fn change_request_project(
    include_extra_entity: bool,
    request_reason_classification: &str,
) -> Vec<u8> {
    let extra_entity = if include_extra_entity {
        r#",{"id":"audit-note","route":"audit-notes","mutationMode":"create_only","fields":[{"id":"label","type":"string","maxLength":16,"classification":"internal"}]}"#
    } else {
        ""
    };
    format!(
        r#"{{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{{"id":"change-request-retention","version":"1","defaultLanguage":"en"}},
          "entities":[{{
            "id":"site","route":"sites","mutationMode":"create_only",
            "fields":[{{"id":"label","type":"string","maxLength":64,"required":true,"classification":"internal"}}]
          }},{{
            "id":"placement","route":"placements","mutationMode":"mutable",
            "changeControl":{{"requiredFor":["patch"]}},
            "fields":[
              {{"id":"site","type":"reference","target":"site","required":true,"classification":"internal"}},
              {{"id":"label","type":"string","maxLength":64,"classification":"internal"}}
            ]
          }},{{
            "id":"placement-correction-request","route":"placement-correction-requests","mutationMode":"mutable",
            "fields":[
              {{"id":"tenant","type":"string","maxLength":64,"required":true,"classification":"internal"}},
              {{"id":"placement","type":"reference","target":"placement","required":true,"classification":"internal"}},
              {{"id":"proposed-site","type":"reference","target":"site","required":true,"classification":"internal"}},
              {{"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"{request_reason_classification}"}}
            ],
            "changeRequest":{{
              "retention":{{"mode":"operator_erase"}},
              "effects":[{{
                "target":{{"fromField":"placement"}},
                "operation":"patch",
                "set":{{"site":{{"fromField":"proposed-site"}}}},
                "clear":["label"]
              }}],
              "review":{{"stages":[{{"id":"review","approvals":1,"excludeSubmitter":true}}]}}
            }}
          }}{extra_entity}],
          "accessProfiles":[{{
            "id":"request-reviewer","default":true,"principalClaim":"principal","grants":[{{
              "entity":"placement-correction-request",
              "operations":["get","list","submit_request","approve_request","reject_request","request_revision"],
              "readableFields":["tenant","placement","proposed-site","reason"],
              "rowBoundaries":[{{"field":"tenant","claim":"tenant","operator":"equals"}}],
              "reviewStages":[{{"stage":"review","targets":[{{"entity":"placement","readableFields":["site","label"]}}]}}]
            }}]
          }},{{
            "id":"request-applier","principalClaim":"principal","grants":[{{
              "entity":"placement-correction-request","operations":["get","apply_request"],
              "readableFields":["tenant","placement"],
              "rowBoundaries":[{{"field":"tenant","claim":"tenant","operator":"equals"}}],
              "applyTargets":[{{"entity":"placement"}}]
            }}]
          }}]
        }}"#
    )
    .into_bytes()
}

fn load_postgres_env() {
    if env::var_os("REGISTRY_SERVER_TEST_DATABASE_URL").is_some() {
        return;
    }
    let Ok(contents) = std::fs::read_to_string("/private/tmp/registry-cr-plain-gqgr39oa/test.env")
    else {
        return;
    };
    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "REGISTRY_SERVER_TEST_DATABASE_URL" {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('\'')
            .and_then(|value| value.strip_suffix('\''))
            .or_else(|| {
                value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
            })
            .unwrap_or(value);
        env::set_var("REGISTRY_SERVER_TEST_DATABASE_URL", value);
    }
}
