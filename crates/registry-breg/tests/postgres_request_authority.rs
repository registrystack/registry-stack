// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::time::Duration;

use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::postgres::{
    begin_record_transaction, initialize_compiled_registry_state_for_test, install_compiled_schema,
    verify_catalog_identity_for_catalog, ClaimContext, ExpectedManagedCatalog, RegistryLockKey,
    RegistryStateTestIdentity,
};
use serde_json::{json, Value};

const REQUEST_ID: &str = "00000000-0000-0000-0000-000000000a01";
const SITE_OLD: &str = "00000000-0000-0000-0000-000000000a02";
const SITE_NEW: &str = "00000000-0000-0000-0000-000000000a03";
const SITE_RETURNING: &str = "00000000-0000-0000-0000-000000000a08";
const PLACEMENT_ID: &str = "00000000-0000-0000-0000-000000000a04";
const REQUEST_HIDDEN: &str = "00000000-0000-0000-0000-000000000a05";
const REQUEST_ERASED_VISIBLE: &str = "00000000-0000-0000-0000-000000000a09";
const REQUEST_ERASED_WRONG_SCOPE: &str = "00000000-0000-0000-0000-000000000a10";
const REQUEST_ERASED_UNMARKED: &str = "00000000-0000-0000-0000-000000000a11";
const PLACEMENT_HIDDEN: &str = "00000000-0000-0000-0000-000000000a06";
const PLACEMENT_ABSENT: &str = "00000000-0000-0000-0000-000000000a07";
const EFFECT_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_request_target_authority_requires_exact_context_and_proposal_target() {
    let registry = compiled_registry();
    let plan = registry.entities()["placement-correction-request"]
        .change_request
        .as_ref()
        .expect("change-request plan compiles");
    let database = TestDatabase::create(1).await;
    let (migration, migration_task) = database.connect_migration().await;

    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("compiled change-request schema installs");
    let catalog = ExpectedManagedCatalog::compiled(&registry);
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: "request-authority",
            environment: "local",
            instance_id: "request-authority-instance",
            database_id: "request-authority-database",
            package_revision: "package-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("test identity initializes");
    verify_catalog_identity_for_catalog(
        &migration,
        &identity,
        &catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("installed catalog matches generated request-authority inventory");

    let site = &registry.entities()["asset-site"];
    let placement = &registry.entities()["asset-placement"];
    let request = &registry.entities()["placement-correction-request"];
    let site_table = quote(&site.physical_table);
    let placement_table = quote(&placement.physical_table);
    let request_table = quote(&request.physical_table);
    let request_source_view = quote(&request.source_relation.sql_name);
    let request_source_id = quote(&request.canonical_id.sql_name);
    let site_tenant = quote(&site.fields["tenant"].physical_name);
    let site_name = quote(&site.fields["name"].physical_name);
    let placement_tenant = quote(&placement.fields["tenant"].physical_name);
    let placement_site = quote(&placement.fields["site"].physical_name);
    let request_tenant_column = &request.fields["tenant"].physical_name;
    let request_reason_column = &request.fields["reason"].physical_name;
    let request_tenant = quote(request_tenant_column);
    let request_placement = quote(&request.fields["placement"].physical_name);
    let request_site = quote(&request.fields["proposed-site"].physical_name);
    let request_reason = quote(request_reason_column);

    migration
        .batch_execute(&format!(
            "SELECT set_config('registry.access_profile', 'seed-writer', true);
             SELECT set_config('registry.principal', 'seed-writer', true);
             SELECT set_config('registry.purpose', '', true);
             SELECT set_config('registry.row_boundaries', '[]', true);
             SELECT set_config('registry.active_package_revision', 'package-1', true);
             INSERT INTO registry_data.{site_table}
                 (record_id, {site_tenant}, {site_name}, active_package_revision)
             VALUES
                 ('{SITE_OLD}'::uuid, 'tenant-a', 'old', 'package-0'),
                 ('{SITE_NEW}'::uuid, 'tenant-a', 'new', 'package-1');
             INSERT INTO registry_data.{placement_table}
                 (record_id, record_revision, {placement_tenant}, {placement_site}, active_package_revision)
             VALUES
                 ('{PLACEMENT_ID}'::uuid, 1, 'tenant-a', '{SITE_OLD}'::uuid, 'package-0'),
                 ('{PLACEMENT_HIDDEN}'::uuid, 1, 'tenant-a', '{SITE_OLD}'::uuid, 'package-0'),
                 ('{PLACEMENT_ABSENT}'::uuid, 1, 'tenant-a', '{SITE_OLD}'::uuid, 'package-0');
             SELECT set_config('registry.access_profile', 'submitter', true);
             SELECT set_config('registry.principal', 'submitter', true);
             SELECT set_config('registry.purpose', '', true);
             SELECT set_config('registry.row_boundaries', '[]', true);
             INSERT INTO registry_data.{request_table}
                 (record_id, record_revision, {request_tenant}, {request_placement}, {request_site}, {request_reason}, active_package_revision)
             VALUES
                 ('{REQUEST_ID}'::uuid, 1, 'tenant-a', '{PLACEMENT_ID}'::uuid, '{SITE_NEW}'::uuid, 'fix site', 'package-0'),
                 ('{REQUEST_HIDDEN}'::uuid, 1, 'tenant-b', '{PLACEMENT_HIDDEN}'::uuid, '{SITE_NEW}'::uuid, 'hidden tenant', 'package-0');
             INSERT INTO registry_internal.registry_request_state
                 (request_entity_id, request_id, owner_reference, state, proposal_version, workflow_revision)
             VALUES
                 ('placement-correction-request', '{REQUEST_ID}'::uuid, 'actor-submit', 'draft', 1, 1),
                 ('placement-correction-request', '{REQUEST_HIDDEN}'::uuid, 'actor-hidden', 'submitted', 1, 1);"
        ))
        .await
        .expect("migration role seeds request and target rows");

    migration
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{request_table} NO FORCE ROW LEVEL SECURITY;
             ALTER TABLE registry_data.{request_table} DISABLE ROW LEVEL SECURITY;
             INSERT INTO registry_data.{request_table}
                 (record_id, record_revision, record_lifecycle, {request_tenant}, active_package_revision)
             VALUES
                 ('{REQUEST_ERASED_VISIBLE}'::uuid, 2, 'tombstoned', 'tenant-a', 'package-1'),
                 ('{REQUEST_ERASED_WRONG_SCOPE}'::uuid, 2, 'tombstoned', 'tenant-b', 'package-1'),
                 ('{REQUEST_ERASED_UNMARKED}'::uuid, 2, 'tombstoned', 'tenant-a', 'package-1');
             ALTER TABLE registry_data.{request_table} ENABLE ROW LEVEL SECURITY;
             ALTER TABLE registry_data.{request_table} FORCE ROW LEVEL SECURITY;
             INSERT INTO registry_internal.registry_request_state
                 (request_entity_id, request_id, owner_reference, state, proposal_version, workflow_revision, detail_erased_at)
             VALUES
                 ('placement-correction-request', '{REQUEST_ERASED_VISIBLE}'::uuid, 'actor-erased', 'applied', 1, 2, transaction_timestamp()),
                 ('placement-correction-request', '{REQUEST_ERASED_WRONG_SCOPE}'::uuid, 'actor-erased', 'applied', 1, 2, transaction_timestamp()),
                 ('placement-correction-request', '{REQUEST_ERASED_UNMARKED}'::uuid, 'actor-erased', 'applied', 1, 2, NULL);"
        ))
        .await
        .expect("migration role seeds erased request provenance rows");

    let request_required_shape = migration
        .query(
            "SELECT column_name, is_nullable
               FROM information_schema.columns
              WHERE table_schema = 'registry_data'
                AND table_name = $1
                AND column_name = ANY($2::text[])
              ORDER BY column_name",
            &[
                &request.physical_table,
                &vec![
                    request_tenant_column.as_str(),
                    request_reason_column.as_str(),
                ],
            ],
        )
        .await
        .expect("request column nullability is visible in PostgreSQL catalog");
    let nullability = request_required_shape
        .iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        nullability[request_tenant_column], "NO",
        "required request row-boundary fields remain retained after erasure"
    );
    assert_eq!(
        nullability[request_reason_column], "YES",
        "required non-boundary request fields are nullable for tombstoned erasure"
    );
    let reason_active_check: i64 = migration
        .query_one(
            "SELECT count(*)
               FROM pg_constraint
              WHERE conrelid = format('registry_data.%I', $1::text)::regclass
                AND contype = 'c'
                AND pg_get_constraintdef(oid) LIKE '%record_lifecycle = ''tombstoned''%'
                AND pg_get_constraintdef(oid) LIKE $2",
            &[
                &request.physical_table,
                &format!("%{} IS NOT NULL%", request_reason_column),
            ],
        )
        .await
        .expect("request conditional required check is visible in PostgreSQL catalog")
        .get(0);
    assert_eq!(
        reason_active_check, 1,
        "active request rows retain the required non-boundary field invariant"
    );

    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let lock_key = RegistryLockKey::derive("request-authority").expect("lock key derives");
    let seed_writer = ClaimContext::for_compiled(
        &registry,
        "asset-site",
        Some("seed-writer".to_owned()),
        "seed-writer",
        None,
        Vec::new(),
    )
    .expect("seed-writer target create claims match compiled profile");
    let submitter = claims(&registry, "submitter", None, None);
    let reviewer = claims(&registry, "reviewer", Some("review"), Some("tenant-a"));
    let reviewer_wrong_tenant = claims(&registry, "reviewer", Some("review"), Some("tenant-b"));
    let applier = claims(&registry, "applier", Some("apply"), Some("tenant-a"));
    let applier_wrong_tenant = claims(&registry, "applier", Some("apply"), Some("tenant-b"));
    let observer = claims(&registry, "observer", None, Some("tenant-a"));
    let steward = placement_claims(&registry, "steward");
    let plain_viewer = placement_claims(&registry, "plain-viewer");

    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &seed_writer,
    )
    .await
    .expect("seed-writer context starts");
    let unbound_create_return = transaction
        .transaction_for_test()
        .query_opt(
            &format!(
                "INSERT INTO registry_data.{site_table} (record_id, {site_tenant}, {site_name})
                 VALUES ('{SITE_RETURNING}'::uuid, 'tenant-a', 'returning')
                 RETURNING record_id::text"
            ),
            &[],
        )
        .await;
    assert!(
        !matches!(unbound_create_return, Ok(Some(_))),
        "create-only profiles cannot receive INSERT RETURNING without the exact server-created record id context"
    );
    transaction
        .rollback()
        .await
        .expect("unbound create-returning proof rolls back");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &seed_writer,
    )
    .await
    .expect("seed-writer create-returning context starts");
    transaction
        .transaction_for_test()
        .execute(
            "SELECT set_config('registry.created_entity_id', 'asset-site', true),
                    set_config('registry.created_record_id', $1, true)",
            &[&SITE_RETURNING],
        )
        .await
        .expect("trusted created record id context installs");
    let returned: String = transaction
        .transaction_for_test()
        .query_one(
            &format!(
                "INSERT INTO registry_data.{site_table} (record_id, {site_tenant}, {site_name})
                 VALUES ('{SITE_RETURNING}'::uuid, 'tenant-a', 'returning')
                 RETURNING record_id::text"
            ),
            &[],
        )
        .await
        .expect("exact server-created record id context allows INSERT RETURNING")
        .get(0);
    assert_eq!(returned, SITE_RETURNING);
    transaction
        .rollback()
        .await
        .expect("bound create-returning proof rolls back");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &applier,
    )
    .await
    .expect("ordinary request GET context starts");
    assert!(
        request_visible(&transaction, &request_table, REQUEST_ERASED_VISIBLE,).await,
        "ordinary request GET can read terminal erased provenance for the scoped row"
    );
    assert!(
        !request_visible(&transaction, &request_table, REQUEST_ERASED_WRONG_SCOPE,).await,
        "ordinary request GET tombstone fallback preserves request row boundaries"
    );
    assert!(
        !request_visible(&transaction, &request_table, REQUEST_ERASED_UNMARKED,).await,
        "ordinary request GET tombstone fallback requires the server erasure marker"
    );
    let listed_erased: i64 = transaction
        .transaction_for_test()
        .query_one(
            &format!(
                "SELECT count(*)
                   FROM registry_source.{request_source_view}
                  WHERE {request_source_id} = '{REQUEST_ERASED_VISIBLE}'::uuid"
            ),
            &[],
        )
        .await
        .expect("request source view remains active-only")
        .get(0);
    assert_eq!(
        listed_erased, 0,
        "list/source views exclude tombstoned requests"
    );
    transaction
        .rollback()
        .await
        .expect("erased request GET proof rolls back");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &applier_wrong_tenant,
    )
    .await
    .expect("wrong-scope request GET context starts");
    assert!(
        !request_visible(&transaction, &request_table, REQUEST_ERASED_VISIBLE,).await,
        "wrong request row boundary cannot read erased provenance"
    );
    transaction
        .rollback()
        .await
        .expect("wrong-scope erased request GET proof rolls back");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &observer,
    )
    .await
    .expect("list-only request context starts");
    assert!(
        !request_visible(&transaction, &request_table, REQUEST_ERASED_VISIBLE,).await,
        "list-only request profiles do not receive the erased GET fallback"
    );
    transaction
        .rollback()
        .await
        .expect("wrong-profile erased request GET proof rolls back");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &submitter,
    )
    .await
    .expect("submitter context starts");
    let invisible_without_prepare: i64 = transaction
        .transaction_for_test()
        .query_one(
            &format!(
                "SELECT count(*) FROM registry_data.{placement_table}
                 WHERE record_id = '{PLACEMENT_ID}'::uuid"
            ),
            &[],
        )
        .await
        .expect("target SELECT without preparation context is an empty RLS view")
        .get(0);
    assert_eq!(invisible_without_prepare, 0);
    set_context(
        transaction.transaction_for_test(),
        "registry.change_request_target_context",
        &target_context(
            "preparation",
            None,
            "submitter",
            None,
            plan.contract_fingerprint.as_str(),
            "actor-submit",
            None,
            &[],
        ),
    )
    .await;
    let visible_for_preparation: i64 = transaction
        .transaction_for_test()
        .query_one(
            &format!(
                "SELECT count(*) FROM registry_data.{placement_table}
                 WHERE record_id = '{PLACEMENT_ID}'::uuid"
            ),
            &[],
        )
        .await
        .expect("owner-bound preparation context can read the exact target row")
        .get(0);
    assert_eq!(visible_for_preparation, 1);
    transaction
        .rollback()
        .await
        .expect("preparation proof rolls back");

    migration
        .execute(
            "UPDATE registry_internal.registry_request_state
                SET state = 'submitted', workflow_revision = workflow_revision + 1
              WHERE request_entity_id = 'placement-correction-request'
                AND request_id = $1::text::uuid",
            &[&REQUEST_ID],
        )
        .await
        .expect("migration role advances request state for review proof");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &reviewer_wrong_tenant,
    )
    .await
    .expect("wrong-tenant reviewer context starts");
    set_context(
        transaction.transaction_for_test(),
        "registry.change_request_action_context",
        &request_action_context(
            "approve_request",
            Some("review"),
            "reviewer",
            Some("review"),
            plan.contract_fingerprint.as_str(),
            "actor-review",
        ),
    )
    .await;
    let denied_by_request_row_boundary = transaction
        .transaction_for_test()
        .execute(
            &format!(
                "UPDATE registry_data.{request_table}
                    SET record_revision = record_revision + 1
                  WHERE record_id = '{REQUEST_ID}'::uuid"
            ),
            &[],
        )
        .await
        .expect("request action UPDATE is evaluated by request row RLS");
    assert_eq!(
        denied_by_request_row_boundary, 0,
        "action context does not bypass the selected request row boundary"
    );
    transaction
        .rollback()
        .await
        .expect("wrong request-row-boundary proof rolls back");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &reviewer,
    )
    .await
    .expect("reviewer context starts");
    let denied_without_action_context = transaction
        .transaction_for_test()
        .execute(
            &format!(
                "UPDATE registry_data.{request_table}
                    SET record_revision = record_revision + 1
                  WHERE record_id = '{REQUEST_ID}'::uuid"
            ),
            &[],
        )
        .await
        .expect("request action UPDATE without action context is filtered by RLS");
    assert_eq!(denied_without_action_context, 0);
    set_context(
        transaction.transaction_for_test(),
        "registry.change_request_action_context",
        &request_action_context(
            "approve_request",
            Some("review"),
            "reviewer",
            Some("review"),
            plan.contract_fingerprint.as_str(),
            "actor-review",
        ),
    )
    .await;
    let allowed_action_update = transaction
        .transaction_for_test()
        .execute(
            &format!(
                "UPDATE registry_data.{request_table}
                    SET record_revision = record_revision + 1
                  WHERE record_id = '{REQUEST_ID}'::uuid"
            ),
            &[],
        )
        .await
        .expect("request action context permits the server-owned revision update");
    assert_eq!(allowed_action_update, 1);
    transaction
        .rollback()
        .await
        .expect("action proof rolls back");

    migration
        .batch_execute(&format!(
            "INSERT INTO registry_internal.registry_request_proposals
                 (request_entity_id, request_id, proposal_version, request_record_revision,
                  contract_fingerprint, effect_digest, snapshot)
             VALUES (
                 'placement-correction-request', '{REQUEST_ID}'::uuid, 1, 1,
                 '{}', '{EFFECT_DIGEST}', '{{}}'::jsonb
             );
             INSERT INTO registry_internal.registry_request_proposals
                 (request_entity_id, request_id, proposal_version, request_record_revision,
                  contract_fingerprint, effect_digest, snapshot)
             VALUES (
                 'placement-correction-request', '{REQUEST_HIDDEN}'::uuid, 1, 1,
                 '{}', '{EFFECT_DIGEST}', '{{}}'::jsonb
             );
             INSERT INTO registry_internal.registry_request_targets
                 (request_entity_id, request_id, proposal_version, target_entity_id,
                  target_record_id, operation, expected_revision, base_snapshot, after_snapshot)
             VALUES (
                 'placement-correction-request', '{REQUEST_HIDDEN}'::uuid, 1,
                 'asset-placement', '{PLACEMENT_HIDDEN}'::uuid, 'patch', 1,
                 '{{}}'::jsonb, '{{}}'::jsonb
             );
             UPDATE registry_internal.registry_request_state
                SET state = 'approved', workflow_revision = workflow_revision + 1
              WHERE request_entity_id = 'placement-correction-request'
                AND request_id = '{REQUEST_ID}'::uuid;",
            plan.contract_fingerprint, plan.contract_fingerprint
        ))
        .await
        .expect("migration role seeds approved proposal without a target binding");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &applier,
    )
    .await
    .expect("applier context starts");
    set_context(
        transaction.transaction_for_test(),
        "registry.change_request_target_context",
        &target_context(
            "application",
            None,
            "applier",
            Some("apply"),
            plan.contract_fingerprint.as_str(),
            "actor-apply",
            Some(1),
            &[json!({"field":"tenant","operator":"equals","values":["tenant-a"]})],
        ),
    )
    .await;
    let denied_without_target_row =
        update_target_site(&transaction, &placement_table, &placement_site).await;
    assert_eq!(
        denied_without_target_row, 0,
        "a setting and proposal do not grant target mutation without target binding"
    );
    transaction
        .rollback()
        .await
        .expect("target-row absence proof rolls back");

    migration
        .batch_execute(&format!(
            "INSERT INTO registry_internal.registry_request_targets
                 (request_entity_id, request_id, proposal_version, target_entity_id,
                  target_record_id, operation, expected_revision, base_snapshot, after_snapshot)
             VALUES (
                 'placement-correction-request', '{REQUEST_ID}'::uuid, 1,
                 'asset-placement', '{PLACEMENT_ID}'::uuid, 'patch', 1,
                 '{{}}'::jsonb, '{{}}'::jsonb
             );"
        ))
        .await
        .expect("migration role seeds immutable target binding");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &plain_viewer,
    )
    .await
    .expect("plain target reader context starts");
    set_context(
        transaction.transaction_for_test(),
        "registry.change_request_presence_context",
        &presence_context(
            "plain-viewer",
            plan.contract_fingerprint.as_str(),
            PLACEMENT_ID,
            &[json!({"field":"tenant","operator":"equals","values":["tenant-a"]})],
        ),
    )
    .await;
    assert!(
        !request_visible(&transaction, &request_table, REQUEST_ID).await,
        "a target reader without requestPresence grant cannot see request rows"
    );
    transaction
        .rollback()
        .await
        .expect("missing-presence-grant proof rolls back");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &steward,
    )
    .await
    .expect("presence target reader context starts");
    assert!(
        !request_visible(&transaction, &request_table, REQUEST_ID).await,
        "request table remains RLS-hidden without presence context"
    );
    set_context(
        transaction.transaction_for_test(),
        "registry.change_request_presence_context",
        &presence_context(
            "steward",
            plan.contract_fingerprint.as_str(),
            PLACEMENT_ABSENT,
            &[json!({"field":"tenant","operator":"equals","values":["tenant-a"]})],
        ),
    )
    .await;
    assert!(
        !request_visible(&transaction, &request_table, REQUEST_ID).await,
        "presence is false when no pending proposal target links the target row"
    );
    set_context(
        transaction.transaction_for_test(),
        "registry.change_request_presence_context",
        &presence_context(
            "steward",
            plan.contract_fingerprint.as_str(),
            PLACEMENT_HIDDEN,
            &[json!({"field":"tenant","operator":"equals","values":["tenant-a"]})],
        ),
    )
    .await;
    assert!(
        !request_visible(&transaction, &request_table, REQUEST_HIDDEN).await,
        "presence request-row boundaries hide otherwise linked requests"
    );
    set_context(
        transaction.transaction_for_test(),
        "registry.change_request_presence_context",
        &presence_context(
            "steward",
            plan.contract_fingerprint.as_str(),
            PLACEMENT_ID,
            &[json!({"field":"tenant","operator":"equals","values":["tenant-a"]})],
        ),
    )
    .await;
    assert!(
        request_visible(&transaction, &request_table, REQUEST_ID).await,
        "exact presence context exposes only the scoped boolean backing row"
    );
    transaction
        .rollback()
        .await
        .expect("presence proof rolls back");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &applier,
    )
    .await
    .expect("applier context starts for wrong-boundary proof");
    set_context(
        transaction.transaction_for_test(),
        "registry.change_request_target_context",
        &target_context(
            "application",
            None,
            "applier",
            Some("apply"),
            plan.contract_fingerprint.as_str(),
            "actor-apply",
            Some(1),
            &[json!({"field":"tenant","operator":"equals","values":["tenant-b"]})],
        ),
    )
    .await;
    let denied_by_boundary =
        update_target_site(&transaction, &placement_table, &placement_site).await;
    assert_eq!(
        denied_by_boundary, 0,
        "target row-boundary mismatch filters the controlled write"
    );
    transaction
        .rollback()
        .await
        .expect("wrong-boundary proof rolls back");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &applier,
    )
    .await
    .expect("applier context starts for exact proof");
    set_context(
        transaction.transaction_for_test(),
        "registry.change_request_target_context",
        &target_context(
            "application",
            None,
            "applier",
            Some("apply"),
            plan.contract_fingerprint.as_str(),
            "actor-apply",
            Some(1),
            &[json!({"field":"tenant","operator":"equals","values":["tenant-a"]})],
        ),
    )
    .await;
    let updated = update_target_site(&transaction, &placement_table, &placement_site).await;
    assert_eq!(
        updated, 1,
        "exact target context applies the controlled write"
    );
    transaction
        .commit()
        .await
        .expect("target application commits");

    drop(migration);
    migration_task.abort();
    database.cleanup().await;
}

async fn update_target_site(
    transaction: &registry_breg::postgres::GuardedTransaction<'_>,
    placement_table: &str,
    placement_site: &str,
) -> u64 {
    transaction
        .transaction_for_test()
        .execute(
            &format!(
                "UPDATE registry_data.{placement_table}
                    SET {placement_site} = '{SITE_NEW}'::uuid,
                        record_revision = record_revision + 1
                  WHERE record_id = '{PLACEMENT_ID}'::uuid"
            ),
            &[],
        )
        .await
        .expect("controlled target UPDATE is evaluated by RLS")
}

async fn request_visible(
    transaction: &registry_breg::postgres::GuardedTransaction<'_>,
    request_table: &str,
    request_id: &str,
) -> bool {
    transaction
        .transaction_for_test()
        .query_one(
            &format!(
                "SELECT EXISTS (
                    SELECT 1
                      FROM registry_data.{request_table}
                     WHERE record_id = $1::text::uuid
                )"
            ),
            &[&request_id],
        )
        .await
        .expect("request presence SELECT is evaluated by RLS")
        .get(0)
}

async fn set_context(transaction: &tokio_postgres::Transaction<'_>, setting: &str, value: &Value) {
    transaction
        .execute(
            "SELECT set_config($1, $2, true)",
            &[&setting, &value.to_string()],
        )
        .await
        .expect("test installs transaction-local context");
}

#[allow(clippy::too_many_arguments)] // Each request and target authority dimension is asserted independently.
fn target_context(
    phase: &str,
    stage: Option<&str>,
    profile: &str,
    purpose: Option<&str>,
    contract_fingerprint: &str,
    actor_reference: &str,
    expected_revision: Option<i64>,
    target_row_boundaries: &[Value],
) -> Value {
    let phase = match stage {
        Some(stage) => json!({"kind": phase, "stage": stage}),
        None => json!({"kind": phase}),
    };
    json!({
        "version": 1,
        "phase": phase,
        "requestEntityId": "placement-correction-request",
        "requestId": REQUEST_ID,
        "proposalVersion": 1,
        "actorReference": actor_reference,
        "contractFingerprint": contract_fingerprint,
        "effectDigest": EFFECT_DIGEST,
        "activePackageRevision": "package-1",
        "selectedAccessProfile": profile,
        "principal": profile,
        "purpose": purpose,
        "effectId": "effect-1",
        "targetEntityId": "asset-placement",
        "targetRecordId": PLACEMENT_ID,
        "operation": "patch",
        "fields": ["site"],
        "expectedRevision": expected_revision,
        "targetRowBoundaries": target_row_boundaries,
    })
}

fn presence_context(
    profile: &str,
    contract_fingerprint: &str,
    target_record_id: &str,
    request_row_boundaries: &[Value],
) -> Value {
    json!({
        "version": 1,
        "requestEntityId": "placement-correction-request",
        "targetEntityId": "asset-placement",
        "targetRecordId": target_record_id,
        "contractFingerprint": contract_fingerprint,
        "activePackageRevision": "package-1",
        "selectedAccessProfile": profile,
        "principal": profile,
        "purpose": null,
        "requestRowBoundaries": request_row_boundaries,
    })
}

fn request_action_context(
    operation: &str,
    stage: Option<&str>,
    profile: &str,
    purpose: Option<&str>,
    contract_fingerprint: &str,
    actor_reference: &str,
) -> Value {
    let action_id = match operation {
        "submit_request" => "submit",
        "approve_request" => "approve",
        "reject_request" => "reject",
        "request_revision" => "request_revision",
        "revise_request" => "revise",
        "cancel_request" => "cancel",
        "apply_request" => "apply",
        _ => "unsupported",
    };
    let route_id = match stage {
        Some(stage) => {
            format!("records.placement-correction-request.request.stages.{stage}.{action_id}")
        }
        None => format!("records.placement-correction-request.request.{action_id}"),
    };
    json!({
        "version": 1,
        "requestEntityId": "placement-correction-request",
        "requestId": REQUEST_ID,
        "proposalVersion": 1,
        "contractFingerprint": contract_fingerprint,
        "actorReference": actor_reference,
        "selectedAccessProfile": profile,
        "principal": profile,
        "purpose": purpose,
        "operation": operation,
        "stage": stage,
        "activePackageRevision": "package-1",
        "routeId": route_id,
    })
}

fn claims(
    registry: &registry_breg::CompiledRegistry,
    profile: &str,
    purpose: Option<&str>,
    tenant: Option<&str>,
) -> ClaimContext {
    let row_boundaries = tenant
        .map(|value| {
            vec![registry_breg::postgres::RowBoundaryContext::Equals {
                field: "tenant".to_owned(),
                value: value.to_owned(),
            }]
        })
        .unwrap_or_default();
    ClaimContext::for_compiled(
        registry,
        "placement-correction-request",
        Some(profile.to_owned()),
        profile,
        purpose.map(str::to_owned),
        row_boundaries,
    )
    .expect("test claims match compiled profile")
}

fn placement_claims(registry: &registry_breg::CompiledRegistry, profile: &str) -> ClaimContext {
    ClaimContext::for_compiled(
        registry,
        "asset-placement",
        Some(profile.to_owned()),
        profile,
        None,
        Vec::new(),
    )
    .expect("test placement claims match compiled profile")
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"change-request-authority","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[
            {
              "id":"asset-site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"name","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}
              ]
            },
            {
              "id":"asset-placement","primaryDataset":"test-dataset","route":"placements","mutationMode":"mutable",
              "changeControl":{"requiredFor":["patch"]},
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"site","type":"reference","target":"asset-site","required":true,"classification":"internal"}
              ]
            },
            {
              "id":"placement-correction-request","primaryDataset":"test-dataset","route":"placement-correction-requests","mutationMode":"mutable",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"},
                {"id":"proposed-site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
                {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}
              ],
              "changeRequest":{
                "effects":[{
                  "target":{"fromField":"placement"},
                  "operation":"patch",
                  "set":{"site":{"fromField":"proposed-site"}}
                }],
                "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
              }
            }
          ],
          "accessProfiles":[
            {
              "id":"seed-writer","default":true,"principalClaim":"registry_principal",
              "grants":[{
                "entity":"asset-site",
                "operations":["create"],
                "readableFields":["tenant","name"],
                "writableFields":["tenant","name"],
                "rowBoundaries": []
              },{
                "entity":"asset-placement",
                "operations":["create"],
                "readableFields":["tenant","site"],
                "writableFields":["tenant","site"],
                "rowBoundaries": []
              }]
            },
            {
              "id":"steward","default":true,"principalClaim":"registry_principal",
              "grants":[{
                "entity":"asset-placement",
                "operations":["get","list"],
                "readableFields":["tenant","site"],
                "requestPresence":[{"requestType":"placement-correction-request","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}],
                "rowBoundaries": []
              }]
            },
            {
              "id":"plain-viewer","principalClaim":"registry_principal",
              "grants":[{
                "entity":"asset-placement",
                "operations":["get","list"],
                "readableFields":["tenant","site"],
                "rowBoundaries": []
              }]
            },
            {
              "id":"submitter","default":true,"principalClaim":"registry_principal",
              "grants":[{
                "entity":"placement-correction-request",
                "operations":["create","get","list","patch","submit_request","revise_request"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "writableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries": []
              }]
            },
            {
              "id":"observer","principalClaim":"registry_principal",
              "grants":[{
                "entity":"placement-correction-request",
                "operations":["list"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
              }]
            },
            {
              "id":"reviewer","principalClaim":"registry_principal","requiredPurposes":["review"],
              "grants":[{
                "entity":"placement-correction-request",
                "operations":["get","list","approve_request","reject_request","request_revision"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "reviewStages":[{
                  "stage":"review",
                  "targets":[{
                    "entity":"asset-placement",
                    "readableFields":["site"],
                    "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                  }]
                }]
              }]
            },
            {
              "id":"applier","principalClaim":"registry_principal","requiredPurposes":["apply"],
              "grants":[{
                "entity":"placement-correction-request",
                "operations":["get","apply_request"],
                "readableFields":["tenant","placement","proposed-site","reason"],
                "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}],
                "applyTargets":[{
                  "entity":"asset-placement",
                  "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                }]
              }]
            }
          ]
        }"#,
    )
    .expect("change-request authority project parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("change-request authority project compiles")
}
