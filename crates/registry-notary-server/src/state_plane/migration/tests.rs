// SPDX-License-Identifier: Apache-2.0

use std::{path::PathBuf, sync::Arc, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_notary_core::{StateConfig, StatePostgresqlConfig, STATE_STORAGE_POSTGRESQL};

use crate::machine_quota::{MachineQuotaLimiter, MachineQuotaOperationOutcome};
use crate::preauth_state::{
    CredentialMaterialization, IssuanceAuthority, IssuanceTransaction, LoginState,
    PreauthorizationState, PreauthorizationStateError, RegistryClientOfferPreflightOutcome,
    RegistryClientOfferReservation, RegistryClientOfferReservationOutcome,
    RegistryClientOfferResponse, RegistryClientTransactionCode,
};
use crate::state_plane::{
    attest_postgres_state_plane_runtime, LoginReserveOutcome, NotaryPostgresStatePlaneError,
    NotaryPostgresStatePlaneReadiness, NotaryPostgresStatePlaneRuntime, NotaryStatePlaneHandle,
    PostgresSensitiveState, PostgresStatePlaneConfig, SensitiveStateError, SensitiveStateKeyConfig,
};

use super::*;

const DATABASE_URL_ENV: &str = "REGISTRY_NOTARY_STATE_POSTGRES_TEST_URL";
const DATABASE_CA_ENV: &str = "REGISTRY_NOTARY_STATE_POSTGRES_TEST_CA";
const POOL_DATABASE_URL_ENV: &str = "REGISTRY_NOTARY_STATE_POOL_TEST_URL";
const SENSITIVE_DATABASE_URL_ENV: &str = "REGISTRY_NOTARY_STATE_SENSITIVE_TEST_URL";
const SENSITIVE_KEY_ENV: &str = "REGISTRY_NOTARY_STATE_SENSITIVE_TEST_KEY";
const SENSITIVE_PROBE_MODE_ENV: &str = "REGISTRY_NOTARY_STATE_SENSITIVE_PROBE_MODE";
const SENSITIVE_PROBE_PIN_ENV: &str = "REGISTRY_NOTARY_STATE_SENSITIVE_PROBE_PIN";
const OWNER_ROLE: &str = "registry_notary_owner_test";
const RUNTIME_ROLE: &str = "registry_notary_runtime_test";
const MIGRATION_ROLE: &str = "registry_notary_migration_test";
const UPGRADE_OWNER_ROLE: &str = "registry_notary_upgrade_owner_test";
const UPGRADE_RUNTIME_ROLE: &str = "registry_notary_upgrade_runtime_test";
const UPGRADE_MIGRATION_ROLE: &str = "registry_notary_upgrade_migration_test";
const RESTORE_SOURCE_OWNER_ROLE: &str = "registry_notary_restore_source_owner";
const RESTORE_SOURCE_RUNTIME_ROLE: &str = "registry_notary_restore_source_runtime";
const RESTORE_SOURCE_MIGRATION_ROLE: &str = "registry_notary_restore_source_migration";
const RESTORE_TARGET_OWNER_ROLE: &str = "registry_notary_restore_target_owner";
const RESTORE_TARGET_RUNTIME_ROLE: &str = "registry_notary_restore_target_runtime";
const RESTORE_TARGET_MIGRATION_ROLE: &str = "registry_notary_restore_target_migration";
const RESTORE_WRONG_OWNER_ROLE: &str = "registry_notary_restore_wrong_owner";
const RESTORE_WRONG_RUNTIME_ROLE: &str = "registry_notary_restore_wrong_runtime";
const RESTORE_WRONG_MIGRATION_ROLE: &str = "registry_notary_restore_wrong_migration";

#[test]
fn schema_fingerprint_is_the_framed_semantic_identity() {
    assert!(STATE_PLANE_SCHEMA_IDENTITY_PREIMAGE_V1.ends_with('\0'));
    for semantic_revision in [
        "schema=notary-owned-private-tables-fixed-typed-api-functions-v1",
        "roles=owner-nologin-migration-assumption-runtime-execute-only-no-private-access-v1",
        "database=postgresql-16-17-18-writable-safe-durability-database-clock-v1",
        "replay=keyed-scope-identifier-one-winner-expiry-replacement-v1",
        "nonce=keyed-generation-reserve-compare-consume-sixty-second-tombstone-v2",
        "evaluation=client-bound-stored-record-v2-atomic-publication-expiry-v1",
        "batch=keyed-request-owner-lease-quota-once-takeover-atomic-completion-stored-response-v2-fifteen-minute-retention-v1",
        "credential-status=insert-only-locked-transition-terminal-revocation-database-clock-effective-expiry-before-suspension-retention-monotonic-updated-at-v2",
        "machine-quota=keyed-principal-fixed-minute-whole-cost-atomic-quota-independent-idempotency-request-conflict-owner-sixty-second-lease-renewal-bounded-completion-final-owner-fence-evaluation-retention-takeover-v4",
        "subject-access-quota=keyed-pseudonym-six-closed-buckets-fixed-windows-canonical-lock-order-caller-denial-order-atomic-all-or-none-check-only-no-mutation-v1",
        "preauthorization-login=keyed-state-capacity-4096-encrypted-single-consume-expiry-live-key-attestation-v2",
        "preauthorization-tx-code=verified-notary-issuer-stable-scope-jti-keyed-pin-verifier-peek-redeem-one-winner-expiry-live-key-attestation-v3",
        "oid4vci-issuance-transaction=keyed-id-encrypted-immutable-record-sha256-uri-commitment-token-nonce-bind-holder-and-request-atomic-one-materialization-encrypted-response-terminal-failure-expiry-v2",
        "issuance-evaluation-consumption=keyed-owner-evaluation-single-lineage-shared-direct-and-offer-expiry-capacity-v1",
        "registry-client-offer=hashed-idempotency-exact-encrypted-response-read-only-preflight-before-side-effects-shared-evaluation-consumption-atomic-client-quota-transaction-and-optional-pin-expiry-capacity-v3",
        "retention=thirteen-fixed-groups-bounded-expiry-prune-skip-locked-saturation-catch-up-v3",
    ] {
        assert!(
            STATE_PLANE_SCHEMA_IDENTITY_PREIMAGE_V1.contains(semantic_revision),
            "semantic fingerprint preimage omitted {semantic_revision}"
        );
    }
    let calculated = Sha256::digest(STATE_PLANE_SCHEMA_IDENTITY_PREIMAGE_V1.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(calculated, STATE_PLANE_SCHEMA_FINGERPRINT_V1);
}

#[test]
fn database_roles_accept_only_safe_unquoted_identifiers() {
    assert!(OwnerDatabaseRole::parse("registry_notary_owner").is_ok());
    assert!(RuntimeDatabaseRole::parse("registry_notary_runtime_1").is_ok());
    for invalid in [
        "",
        "1owner",
        "Owner",
        "owner-role",
        "owner;select",
        "role name",
    ] {
        assert!(OwnerDatabaseRole::parse(invalid).is_err());
        assert!(RuntimeDatabaseRole::parse(invalid).is_err());
    }
}

#[test]
fn migration_uses_fixed_security_definer_api_without_generic_grants() {
    assert_eq!(
        POSTGRES_STATE_PLANE_MIGRATION_V1
            .matches("SECURITY DEFINER")
            .count(),
        EXPECTED_API_FUNCTION_COUNT_V1 as usize
    );
    let acl = state_plane_acl_sql(
        &RuntimeDatabaseRole::parse("registry_notary_runtime").expect("valid role"),
    );
    assert!(!acl.contains("GRANT EXECUTE ON ALL FUNCTIONS"));
    assert!(
        acl.contains("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA registry_notary_api FROM PUBLIC")
    );
    for table in [
        "replay_identifier",
        "consumable_nonce",
        "evaluation",
        "batch_idempotency",
        "credential_status",
        "machine_quota",
        "machine_quota_operation",
        "subject_access_quota",
        "preauthorization_login_state",
        "preauthorization_tx_code",
        "oid4vci_issuance_transaction",
        "issuance_evaluation_consumption",
        "registry_client_offer",
    ] {
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains(table));
    }
}

fn previous_state_plane_migration_v1() -> String {
    fn remove_unique_range(sql: &mut String, start: &str, end: &str) {
        assert_eq!(
            sql.matches(start).count(),
            1,
            "previous migration start marker must be unique"
        );
        let start_offset = sql.find(start).expect("checked start marker");
        let end_offset = sql[start_offset..]
            .find(end)
            .map(|offset| start_offset + offset)
            .expect("previous migration end marker");
        sql.replace_range(start_offset..end_offset, "");
    }

    let mut sql = POSTGRES_STATE_PLANE_MIGRATION_V1.to_string();
    remove_unique_range(
        &mut sql,
        "CREATE TABLE IF NOT EXISTS registry_notary_private.machine_quota_operation",
        "CREATE TABLE IF NOT EXISTS registry_notary_private.subject_access_quota",
    );
    remove_unique_range(
        &mut sql,
        "CREATE TABLE IF NOT EXISTS registry_notary_private.issuance_evaluation_consumption",
        "ALTER DEFAULT PRIVILEGES IN SCHEMA registry_notary_private",
    );
    remove_unique_range(
        &mut sql,
        "CREATE OR REPLACE FUNCTION registry_notary_api.evaluation_issuance_consume_v1",
        "CREATE OR REPLACE FUNCTION registry_notary_api.oid4vci_transaction_reserve_v1",
    );
    remove_unique_range(
        &mut sql,
        "CREATE OR REPLACE FUNCTION registry_notary_api.machine_quota_debit_once_v1",
        "CREATE OR REPLACE FUNCTION registry_notary_api.subject_access_quota_debit_v1",
    );

    let v_now_key_extension = r#"        UNION ALL
        SELECT 1 FROM registry_notary_private.issuance_evaluation_consumption
         WHERE expires_at > v_now AND key_id <> p_key_id
        UNION ALL
        SELECT 1 FROM registry_notary_private.registry_client_offer
         WHERE purge_after > v_now AND key_id <> p_key_id
"#;
    assert_eq!(sql.matches(v_now_key_extension).count(), 3);
    sql = sql.replace(v_now_key_extension, "");
    let statement_key_extension = r#"            UNION ALL
            SELECT 1 FROM registry_notary_private.issuance_evaluation_consumption
             WHERE expires_at > pg_catalog.statement_timestamp() AND key_id <> p_key_id
            UNION ALL
            SELECT 1 FROM registry_notary_private.registry_client_offer
             WHERE purge_after > pg_catalog.statement_timestamp() AND key_id <> p_key_id
"#;
    assert_eq!(sql.matches(statement_key_extension).count(), 1);
    sql = sql.replace(statement_key_extension, "");
    remove_unique_range(
        &mut sql,
        r#"    WITH candidates AS (
        SELECT principal_hash, operation_hash
          FROM registry_notary_private.machine_quota_operation"#,
        r#"    WITH candidates AS (
        SELECT bucket_kind, key_hash
          FROM registry_notary_private.subject_access_quota"#,
    );
    remove_unique_range(
        &mut sql,
        r#"    WITH candidates AS (
        SELECT evaluation_hash
          FROM registry_notary_private.issuance_evaluation_consumption"#,
        "    RETURN QUERY SELECT v_total, v_saturated;",
    );
    assert_eq!(sql.matches("SECURITY DEFINER").count(), 31);
    assert!(!sql.contains("issuance_evaluation_consumption"));
    assert!(!sql.contains("registry_client_offer"));
    assert!(!sql.contains("machine_quota_operation"));
    sql
}

#[test]
fn preceding_migration_fixture_is_exactly_narrowed() {
    previous_state_plane_migration_v1();
}

async fn assert_previous_state_plane_upgrade_contract(
    database_url: &str,
    admin: &Client,
) -> Result<(), Box<dyn std::error::Error>> {
    admin
        .batch_execute(&format!(
            "CREATE ROLE {UPGRADE_OWNER_ROLE} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
                 NOREPLICATION NOBYPASSRLS;\n\
             CREATE ROLE {UPGRADE_RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
                 NOREPLICATION NOBYPASSRLS;\n\
             CREATE ROLE {UPGRADE_MIGRATION_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
                 NOREPLICATION NOBYPASSRLS;\n\
             GRANT {UPGRADE_OWNER_ROLE} TO {UPGRADE_MIGRATION_ROLE};\n\
             GRANT CREATE ON DATABASE postgres TO {UPGRADE_OWNER_ROLE};"
        ))
        .await?;
    let (mut migration, migration_driver) =
        connect_as(database_url, UPGRADE_MIGRATION_ROLE).await?;
    let transaction = migration.transaction().await?;
    transaction
        .batch_execute(&format!(
            "SET LOCAL ROLE {UPGRADE_OWNER_ROLE};\n{}",
            previous_state_plane_migration_v1()
        ))
        .await?;
    let roles = transaction
        .query_one(
            "SELECT owner.oid::bigint, runtime.oid::bigint\n\
               FROM pg_catalog.pg_roles AS owner\n\
               JOIN pg_catalog.pg_roles AS runtime ON runtime.rolname = $2\n\
              WHERE owner.rolname = $1",
            &[&UPGRADE_OWNER_ROLE, &UPGRADE_RUNTIME_ROLE],
        )
        .await?;
    let owner_oid: i64 = roles.get(0);
    let runtime_oid: i64 = roles.get(1);
    transaction
        .execute(
            "INSERT INTO registry_notary_private.schema_metadata (\n\
                 singleton, capability_id, schema_version, schema_fingerprint,\n\
                 owner_role_oid, runtime_role_oid\n\
             ) VALUES (TRUE, $1, $2, $3, $4::bigint::oid, $5::bigint::oid)",
            &[
                &STATE_PLANE_CAPABILITY_V1,
                &STATE_PLANE_SCHEMA_VERSION_V1,
                &PREVIOUS_STATE_PLANE_SCHEMA_FINGERPRINT_V1,
                &owner_oid,
                &runtime_oid,
            ],
        )
        .await?;
    let live_scope = vec![0xa1_u8; 32];
    let live_identifier = vec![0xa2_u8; 32];
    let live_state = vec![0xa3_u8; 32];
    let live_key = vec![0xa4_u8; 32];
    transaction
        .execute(
            "INSERT INTO registry_notary_private.replay_identifier (\n\
                 scope_hash, identifier_hash, expires_at\n\
             ) VALUES ($1, $2, pg_catalog.clock_timestamp() + interval '1 hour')",
            &[&live_scope, &live_identifier],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO registry_notary_private.preauthorization_login_state (\n\
                 state_hash, credential_configuration_id, key_id, aead_nonce,\n\
                 ciphertext, expires_at\n\
             ) VALUES ($1, 'upgrade-live-state', $2, $3, $4,\n\
                 pg_catalog.clock_timestamp() + interval '1 hour')",
            &[
                &live_state,
                &live_key,
                &vec![0xa5_u8; 12],
                &vec![0xa6_u8; 17],
            ],
        )
        .await?;
    transaction.commit().await?;

    let server_major = attest_server(admin).await?;
    assert_eq!(
        catalog_definition_fingerprint(admin).await?,
        expected_previous_catalog_definition_fingerprint(server_major)?,
        "the upgrade fixture must exactly reproduce the preceding catalog"
    );
    let installed = install_postgres_state_plane_v1(
        &mut migration,
        &OwnerDatabaseRole::parse(UPGRADE_OWNER_ROLE)?,
        &RuntimeDatabaseRole::parse(UPGRADE_RUNTIME_ROLE)?,
    )
    .await?;
    assert_eq!(installed.server_major, server_major);
    assert_eq!(
        admin
            .query_one(
                "SELECT schema_fingerprint FROM registry_notary_private.schema_metadata",
                &[],
            )
            .await?
            .get::<_, String>(0),
        STATE_PLANE_SCHEMA_FINGERPRINT_V1
    );
    assert_eq!(
        admin
            .query_one(
                "SELECT count(*)::bigint FROM registry_notary_private.replay_identifier\n\
                  WHERE scope_hash = $1 AND identifier_hash = $2",
                &[&live_scope, &live_identifier],
            )
            .await?
            .get::<_, i64>(0),
        1,
        "forward migration must preserve preceding live rows"
    );
    assert_eq!(
        admin
            .query_one(
                "SELECT count(*)::bigint\n\
                   FROM registry_notary_private.preauthorization_login_state\n\
                  WHERE state_hash = $1 AND key_id = $2",
                &[&live_state, &live_key],
            )
            .await?
            .get::<_, i64>(0),
        1,
        "forward migration must preserve preceding live sensitive rows"
    );
    let new_table_counts = admin
        .query_one(
            "SELECT\n\
                 (SELECT count(*)::bigint FROM \
                    registry_notary_private.issuance_evaluation_consumption),\n\
                 (SELECT count(*)::bigint FROM \
                    registry_notary_private.registry_client_offer),\n\
                 (SELECT count(*)::bigint FROM \
                    registry_notary_private.machine_quota_operation)",
            &[],
        )
        .await?;
    assert_eq!(new_table_counts.get::<_, i64>(0), 0);
    assert_eq!(new_table_counts.get::<_, i64>(1), 0);
    assert_eq!(new_table_counts.get::<_, i64>(2), 0);

    let (runtime, runtime_driver) = connect_as(database_url, UPGRADE_RUNTIME_ROLE).await?;
    assert_eq!(attest_postgres_state_plane_v1(&runtime).await?, installed);
    assert_eq!(
        runtime
            .query_one(
                "SELECT registry_notary_api.evaluation_issuance_consume_v1(\n\
                     $1, $2, pg_catalog.clock_timestamp() + interval '1 hour')",
                &[&vec![0xa7_u8; 32], &live_key],
            )
            .await?
            .get::<_, i16>(0),
        1
    );
    install_postgres_state_plane_v1(
        &mut migration,
        &OwnerDatabaseRole::parse(UPGRADE_OWNER_ROLE)?,
        &RuntimeDatabaseRole::parse(UPGRADE_RUNTIME_ROLE)?,
    )
    .await?;

    drop(runtime);
    runtime_driver.abort();
    drop(migration);
    migration_driver.abort();
    admin
        .batch_execute(&format!(
            "DROP SCHEMA registry_notary_api CASCADE;\n\
             DROP SCHEMA registry_notary_private CASCADE;\n\
             DROP ROLE {UPGRADE_RUNTIME_ROLE};\n\
             DROP ROLE {UPGRADE_MIGRATION_ROLE};\n\
             REVOKE CREATE ON DATABASE postgres FROM {UPGRADE_OWNER_ROLE};\n\
             DROP ROLE {UPGRADE_OWNER_ROLE};"
        ))
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a dedicated REGISTRY_NOTARY_STATE_POSTGRES_TEST_URL"]
async fn postgres_v1_logical_restore_rebind_requires_exact_owner_and_catalog(
) -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var(DATABASE_URL_ENV)?;
    let (admin, admin_driver) = connect_as(&database_url, "postgres").await?;
    let database_name: String = admin
        .query_one("SELECT current_database()", &[])
        .await?
        .get(0);
    if database_name != "postgres" {
        return Err("the dedicated conformance database must be named postgres".into());
    }
    let occupied: bool = admin
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace\n\
               WHERE nspname IN ('registry_notary_private', 'registry_notary_api'))",
            &[],
        )
        .await?
        .get(0);
    if occupied {
        return Err("the dedicated conformance database is not empty".into());
    }
    admin
        .batch_execute(&format!(
            "CREATE ROLE {RESTORE_SOURCE_OWNER_ROLE} NOLOGIN NOSUPERUSER NOCREATEDB \
                 NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n\
             CREATE ROLE {RESTORE_SOURCE_RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB \
                 NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n\
             CREATE ROLE {RESTORE_SOURCE_MIGRATION_ROLE} LOGIN NOSUPERUSER NOCREATEDB \
                 NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n\
             GRANT {RESTORE_SOURCE_OWNER_ROLE} TO {RESTORE_SOURCE_MIGRATION_ROLE};\n\
             GRANT CREATE ON DATABASE postgres TO {RESTORE_SOURCE_OWNER_ROLE};"
        ))
        .await?;
    let (mut source_migration, source_migration_driver) =
        connect_as(&database_url, RESTORE_SOURCE_MIGRATION_ROLE).await?;
    install_postgres_state_plane_v1(
        &mut source_migration,
        &OwnerDatabaseRole::parse(RESTORE_SOURCE_OWNER_ROLE)?,
        &RuntimeDatabaseRole::parse(RESTORE_SOURCE_RUNTIME_ROLE)?,
    )
    .await?;
    let source_roles = metadata_roles_for_exact_v1(&admin).await?;
    drop(source_migration);
    source_migration_driver.abort();

    admin
        .batch_execute(&format!(
            "CREATE ROLE {RESTORE_TARGET_OWNER_ROLE} NOLOGIN NOSUPERUSER NOCREATEDB \
                 NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n\
             CREATE ROLE {RESTORE_TARGET_RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB \
                 NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n\
             CREATE ROLE {RESTORE_TARGET_MIGRATION_ROLE} LOGIN NOSUPERUSER NOCREATEDB \
                 NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n\
             GRANT {RESTORE_TARGET_OWNER_ROLE} TO {RESTORE_TARGET_MIGRATION_ROLE};\n\
             GRANT CREATE ON DATABASE postgres TO {RESTORE_TARGET_OWNER_ROLE};\n\
             CREATE ROLE {RESTORE_WRONG_OWNER_ROLE} NOLOGIN NOSUPERUSER NOCREATEDB \
                 NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n\
             CREATE ROLE {RESTORE_WRONG_RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB \
                 NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n\
             CREATE ROLE {RESTORE_WRONG_MIGRATION_ROLE} LOGIN NOSUPERUSER NOCREATEDB \
                 NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n\
             GRANT {RESTORE_WRONG_OWNER_ROLE} TO {RESTORE_WRONG_MIGRATION_ROLE};\n\
             REASSIGN OWNED BY {RESTORE_SOURCE_OWNER_ROLE} \
                 TO {RESTORE_TARGET_OWNER_ROLE};\n\
             DROP OWNED BY {RESTORE_SOURCE_RUNTIME_ROLE};\n\
             GRANT ALL ON SCHEMA registry_notary_private TO PUBLIC;\n\
             GRANT ALL ON SCHEMA registry_notary_api TO PUBLIC;\n\
             GRANT ALL ON ALL TABLES IN SCHEMA registry_notary_private TO PUBLIC;\n\
             GRANT ALL ON ALL SEQUENCES IN SCHEMA registry_notary_private TO PUBLIC;\n\
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA registry_notary_private TO PUBLIC;\n\
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA registry_notary_api TO PUBLIC;\n\
             REVOKE CREATE ON DATABASE postgres FROM {RESTORE_SOURCE_OWNER_ROLE};\n\
             REVOKE {RESTORE_SOURCE_OWNER_ROLE} FROM {RESTORE_SOURCE_MIGRATION_ROLE};\n\
             DROP ROLE {RESTORE_SOURCE_RUNTIME_ROLE};\n\
             DROP ROLE {RESTORE_SOURCE_MIGRATION_ROLE};\n\
             DROP ROLE {RESTORE_SOURCE_OWNER_ROLE};"
        ))
        .await?;

    let target_owner_oid: i64 = admin
        .query_one(
            "SELECT oid::bigint FROM pg_catalog.pg_roles WHERE rolname = $1",
            &[&RESTORE_TARGET_OWNER_ROLE],
        )
        .await?
        .get(0);
    let target_runtime_oid: i64 = admin
        .query_one(
            "SELECT oid::bigint FROM pg_catalog.pg_roles WHERE rolname = $1",
            &[&RESTORE_TARGET_RUNTIME_ROLE],
        )
        .await?
        .get(0);
    let target_roles = BoundRoleOids {
        owner: target_owner_oid,
        runtime: target_runtime_oid,
    };
    assert_ne!(source_roles, target_roles, "fresh roles must shift OIDs");
    assert_eq!(
        metadata_roles_for_exact_v1(&admin).await?,
        source_roles,
        "logical restore preserves the source metadata OIDs"
    );
    let target_runtime_had_execute: bool = admin
        .query_one(
            "SELECT pg_catalog.has_function_privilege(\n\
                 $1, 'registry_notary_api.attest_v1()', 'EXECUTE')",
            &[&RESTORE_TARGET_RUNTIME_ROLE],
        )
        .await?
        .get(0);
    assert!(
        target_runtime_had_execute,
        "ACL-stripped restore exposes default PUBLIC function execution before repair"
    );

    let (mut target_migration, target_migration_driver) =
        connect_as(&database_url, RESTORE_TARGET_MIGRATION_ROLE).await?;
    let rebound = install_postgres_state_plane_v1(
        &mut target_migration,
        &OwnerDatabaseRole::parse(RESTORE_TARGET_OWNER_ROLE)?,
        &RuntimeDatabaseRole::parse(RESTORE_TARGET_RUNTIME_ROLE)?,
    )
    .await?;
    assert_eq!(metadata_roles_for_exact_v1(&admin).await?, target_roles);
    let (target_runtime, target_runtime_driver) =
        connect_as(&database_url, RESTORE_TARGET_RUNTIME_ROLE).await?;
    assert_eq!(
        attest_postgres_state_plane_v1(&target_runtime).await?,
        rebound
    );
    let public_acl_repaired: bool = admin
        .query_one(
            "SELECT NOT pg_catalog.has_schema_privilege(\n\
                 $1, 'registry_notary_private', 'USAGE')\n\
               AND NOT pg_catalog.has_schema_privilege(\n\
                 $1, 'registry_notary_api', 'USAGE')\n\
               AND NOT pg_catalog.has_table_privilege(\n\
                 $1, 'registry_notary_private.schema_metadata', 'SELECT')",
            &[&RESTORE_WRONG_RUNTIME_ROLE],
        )
        .await?
        .get(0);
    assert!(
        public_acl_repaired,
        "restore rebind must remove PUBLIC schema and private-table privileges"
    );

    let metadata_before_rejected_rebind = metadata_roles_for_exact_v1(&admin).await?;
    let (mut wrong_migration, wrong_migration_driver) =
        connect_as(&database_url, RESTORE_WRONG_MIGRATION_ROLE).await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut wrong_migration,
            &OwnerDatabaseRole::parse(RESTORE_WRONG_OWNER_ROLE)?,
            &RuntimeDatabaseRole::parse(RESTORE_WRONG_RUNTIME_ROLE)?,
        )
        .await,
        Err(StatePlaneMigrationError::CapabilityDrift)
    );
    assert_eq!(
        metadata_roles_for_exact_v1(&admin).await?,
        metadata_before_rejected_rebind,
        "wrong-owner rebind must roll back metadata changes"
    );
    let wrong_runtime_gained_execute: bool = admin
        .query_one(
            "SELECT pg_catalog.has_function_privilege(\n\
                 $1, 'registry_notary_api.attest_v1()', 'EXECUTE')",
            &[&RESTORE_WRONG_RUNTIME_ROLE],
        )
        .await?
        .get(0);
    assert!(
        !wrong_runtime_gained_execute,
        "rejected ownership rebind must not grant runtime execution"
    );

    admin
        .batch_execute(
            "ALTER FUNCTION registry_notary_api.replay_insert_v1(\n\
                 bytea, bytea, timestamptz) IMMUTABLE",
        )
        .await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut target_migration,
            &OwnerDatabaseRole::parse(RESTORE_TARGET_OWNER_ROLE)?,
            &RuntimeDatabaseRole::parse(RESTORE_TARGET_RUNTIME_ROLE)?,
        )
        .await,
        Err(StatePlaneMigrationError::CapabilityDrift)
    );
    assert_eq!(metadata_roles_for_exact_v1(&admin).await?, target_roles);
    let drift_remains: bool = admin
        .query_one(
            "SELECT function.provolatile = 'i'\n\
               FROM pg_catalog.pg_proc AS function\n\
               JOIN pg_catalog.pg_namespace AS namespace\n\
                 ON namespace.oid = function.pronamespace\n\
              WHERE namespace.nspname = 'registry_notary_api'\n\
                AND function.proname = 'replay_insert_v1'",
            &[],
        )
        .await?
        .get(0);
    assert!(
        drift_remains,
        "rejected install must not repair catalog drift"
    );

    drop(target_runtime);
    target_runtime_driver.abort();
    drop(target_migration);
    target_migration_driver.abort();
    drop(wrong_migration);
    wrong_migration_driver.abort();
    admin
        .batch_execute(&format!(
            "DROP SCHEMA registry_notary_api CASCADE;\n\
             DROP SCHEMA registry_notary_private CASCADE;\n\
             REVOKE {RESTORE_TARGET_OWNER_ROLE} FROM {RESTORE_TARGET_MIGRATION_ROLE};\n\
             REVOKE CREATE ON DATABASE postgres FROM {RESTORE_TARGET_OWNER_ROLE};\n\
             DROP ROLE {RESTORE_TARGET_RUNTIME_ROLE};\n\
             DROP ROLE {RESTORE_TARGET_MIGRATION_ROLE};\n\
             DROP ROLE {RESTORE_TARGET_OWNER_ROLE};\n\
             REVOKE {RESTORE_WRONG_OWNER_ROLE} FROM {RESTORE_WRONG_MIGRATION_ROLE};\n\
             DROP ROLE {RESTORE_WRONG_RUNTIME_ROLE};\n\
             DROP ROLE {RESTORE_WRONG_MIGRATION_ROLE};\n\
             DROP ROLE {RESTORE_WRONG_OWNER_ROLE};"
        ))
        .await?;
    drop(admin);
    admin_driver.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires a dedicated REGISTRY_NOTARY_STATE_POSTGRES_TEST_URL"]
async fn postgres_v1_typed_state_contracts_and_drift_rejection(
) -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var(DATABASE_URL_ENV)?;
    let (admin, admin_driver) = connect_as(&database_url, "postgres").await?;
    let database_name: String = admin
        .query_one("SELECT current_database()", &[])
        .await?
        .get(0);
    if database_name != "postgres" {
        return Err("the dedicated conformance database must be named postgres".into());
    }
    let occupied: bool = admin
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace\n\
               WHERE nspname IN ('registry_notary_private', 'registry_notary_api'))\n\
             OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles\n\
               WHERE rolname IN ($1, $2, $3, $4, $5, $6))",
            &[
                &OWNER_ROLE,
                &RUNTIME_ROLE,
                &MIGRATION_ROLE,
                &UPGRADE_OWNER_ROLE,
                &UPGRADE_RUNTIME_ROLE,
                &UPGRADE_MIGRATION_ROLE,
            ],
        )
        .await?
        .get(0);
    if occupied {
        return Err("the dedicated conformance database is not empty".into());
    }
    assert_previous_state_plane_upgrade_contract(&database_url, &admin).await?;
    admin
        .batch_execute(&format!(
            "CREATE ROLE {OWNER_ROLE} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
                 NOREPLICATION NOBYPASSRLS;\n\
             CREATE ROLE {RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
                 NOREPLICATION NOBYPASSRLS;\n\
             CREATE ROLE {MIGRATION_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
                 NOREPLICATION NOBYPASSRLS;\n\
             GRANT {OWNER_ROLE} TO {MIGRATION_ROLE};\n\
             GRANT CREATE ON DATABASE postgres TO {OWNER_ROLE};"
        ))
        .await?;

    let (mut migration, migration_driver) = connect_as(&database_url, MIGRATION_ROLE).await?;
    let installed = install_postgres_state_plane_v1(
        &mut migration,
        &OwnerDatabaseRole::parse(OWNER_ROLE)?,
        &RuntimeDatabaseRole::parse(RUNTIME_ROLE)?,
    )
    .await?;
    assert!((16..=18).contains(&installed.server_major));

    let (runtime, runtime_driver) = connect_as(&database_url, RUNTIME_ROLE).await?;
    let attested = attest_postgres_state_plane_v1(&runtime).await?;
    assert_eq!(attested, installed);

    let invalid_token_buckets = vec!["invalid_token_per_client_address".to_string()];
    let invalid_token_hashes = vec![vec![0x11; 32]];
    let invalid_token_limits = vec![2];
    let invalid_token_windows = vec![60];
    assert_eq!(
        subject_access_quota_decision(
            &runtime,
            SUBJECT_ACCESS_QUOTA_CHECK_SQL,
            &invalid_token_buckets,
            &invalid_token_hashes,
            &invalid_token_limits,
            &invalid_token_windows,
        )
        .await?,
        (true, None)
    );
    assert_eq!(
        subject_access_quota_decision(
            &runtime,
            SUBJECT_ACCESS_QUOTA_CHECK_SQL,
            &invalid_token_buckets,
            &invalid_token_hashes,
            &invalid_token_limits,
            &invalid_token_windows,
        )
        .await?,
        (true, None),
        "availability checks must not consume invalid-token quota"
    );

    let (runtime_peer, runtime_peer_driver) = connect_as(&database_url, RUNTIME_ROLE).await?;
    let concurrent_buckets = vec!["per_principal".to_string()];
    let concurrent_hashes = vec![vec![0x55; 32]];
    let concurrent_limits = vec![1];
    let concurrent_windows = vec![60];
    let (first_instance, second_instance) = tokio::join!(
        subject_access_quota_decision(
            &runtime,
            SUBJECT_ACCESS_QUOTA_DEBIT_SQL,
            &concurrent_buckets,
            &concurrent_hashes,
            &concurrent_limits,
            &concurrent_windows,
        ),
        subject_access_quota_decision(
            &runtime_peer,
            SUBJECT_ACCESS_QUOTA_DEBIT_SQL,
            &concurrent_buckets,
            &concurrent_hashes,
            &concurrent_limits,
            &concurrent_windows,
        )
    );
    let first_instance = first_instance?;
    let second_instance = second_instance?;
    assert_ne!(
        first_instance.0, second_instance.0,
        "exactly one concurrent runtime may consume the last unit"
    );
    assert_eq!(
        [first_instance, second_instance]
            .into_iter()
            .filter(|decision| decision.0)
            .count(),
        1
    );

    assert_eq!(
        subject_access_quota_decision(
            &runtime_peer,
            SUBJECT_ACCESS_QUOTA_DEBIT_SQL,
            &invalid_token_buckets,
            &invalid_token_hashes,
            &invalid_token_limits,
            &invalid_token_windows,
        )
        .await?,
        (true, None)
    );
    drop(runtime_peer);
    runtime_peer_driver.abort();

    let (runtime_restarted, runtime_restarted_driver) =
        connect_as(&database_url, RUNTIME_ROLE).await?;
    assert_eq!(
        subject_access_quota_decision(
            &runtime_restarted,
            SUBJECT_ACCESS_QUOTA_DEBIT_SQL,
            &invalid_token_buckets,
            &invalid_token_hashes,
            &invalid_token_limits,
            &invalid_token_windows,
        )
        .await?,
        (true, None),
        "a restarted runtime must observe and continue the shared bucket"
    );
    drop(runtime_restarted);
    runtime_restarted_driver.abort();
    assert_eq!(
        subject_access_quota_decision(
            &runtime,
            SUBJECT_ACCESS_QUOTA_CHECK_SQL,
            &invalid_token_buckets,
            &invalid_token_hashes,
            &invalid_token_limits,
            &invalid_token_windows,
        )
        .await?,
        (false, Some("invalid_token_per_client_address".to_string())),
        "the original runtime must observe debits made by peer and restarted runtimes"
    );

    let grouped_buckets = vec![
        "per_principal".to_string(),
        "per_holder_issuance".to_string(),
    ];
    let grouped_hashes = vec![vec![0x22; 32], vec![0x33; 32]];
    let grouped_limits = vec![1, 0];
    let grouped_windows = vec![60, 3600];
    assert_eq!(
        subject_access_quota_decision(
            &runtime,
            SUBJECT_ACCESS_QUOTA_DEBIT_SQL,
            &grouped_buckets,
            &grouped_hashes,
            &grouped_limits,
            &grouped_windows,
        )
        .await?,
        (false, Some("per_holder_issuance".to_string()))
    );
    assert_eq!(
        subject_access_quota_decision(
            &runtime,
            SUBJECT_ACCESS_QUOTA_DEBIT_SQL,
            &["per_principal".to_string()],
            &[vec![0x22; 32]],
            &[1],
            &[60],
        )
        .await?,
        (true, None),
        "a denied grouped debit must not partially consume an allowed bucket"
    );

    assert_replay_and_nonce_contracts(&database_url, &runtime, &admin).await?;
    assert_evaluation_and_batch_contracts(&database_url, &runtime, &admin).await?;
    assert_credential_status_and_machine_quota_contracts(&database_url, &runtime, &admin).await?;
    assert_preauthorization_contracts(&database_url, &runtime, &admin).await?;
    assert_sensitive_adapter_contract(&database_url, &admin).await?;
    assert_retention_contract(&runtime, &admin).await?;
    assert_runtime_pool_contract(&database_url).await?;

    admin
        .batch_execute(
            "ALTER FUNCTION registry_notary_api.replay_insert_v1(\n\
                 bytea, bytea, timestamptz) IMMUTABLE",
        )
        .await?;
    assert_eq!(
        attest_postgres_state_plane_v1(&runtime).await,
        Err(StatePlaneMigrationError::CapabilityDrift)
    );

    drop(runtime);
    runtime_driver.abort();
    drop(migration);
    migration_driver.abort();
    admin
        .batch_execute(&format!(
            "DROP SCHEMA registry_notary_api CASCADE;\n\
             DROP SCHEMA registry_notary_private CASCADE;\n\
             DROP ROLE {RUNTIME_ROLE};\n\
             DROP ROLE {MIGRATION_ROLE};\n\
             REVOKE CREATE ON DATABASE postgres FROM {OWNER_ROLE};\n\
             DROP ROLE {OWNER_ROLE};"
        ))
        .await?;
    drop(admin);
    admin_driver.abort();
    Ok(())
}

async fn assert_runtime_pool_contract(
    database_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime_url = database_url.replacen("postgres@", &format!("{RUNTIME_ROLE}@"), 1);
    if runtime_url == database_url {
        return Err("pool test URL does not contain the expected dedicated admin role".into());
    }
    // SAFETY: the conformance harness runs this ignored test by exact name
    // in its own process, so no concurrent test reads this unique variable.
    unsafe { std::env::set_var(POOL_DATABASE_URL_ENV, &runtime_url) };
    let config = PostgresStatePlaneConfig::new(
        POOL_DATABASE_URL_ENV,
        Some(PathBuf::from(std::env::var(DATABASE_CA_ENV)?)),
        // Exercise the pool contract with the implementer-facing defaults.
        // Artificially short activation deadlines are unreliable on hosted
        // runners and do not represent the production readiness boundary.
        Duration::from_secs(5),
        Duration::from_secs(2),
        1,
    )?;
    let pooled = Arc::new(NotaryPostgresStatePlaneRuntime::connect(&config).await?);
    assert_eq!(pooled.created_session_count(), 1);

    for _ in 0..3 {
        let session = pooled.open_domain_session().await?;
        session
            .run_operation(session.client().simple_query("SELECT 1"))
            .await?;
    }
    assert_eq!(
        pooled.created_session_count(),
        1,
        "sequential state operations must reuse one physical session"
    );

    let held = pooled.open_domain_session().await?;
    let wait_started = tokio::time::Instant::now();
    assert!(matches!(
        pooled.open_domain_session().await,
        Err(NotaryPostgresStatePlaneError::OperationUnavailable)
    ));
    let waited = wait_started.elapsed();
    assert!(
        waited >= Duration::from_secs(1) && waited < Duration::from_secs(5),
        "saturated pool admission must honor the configured operation deadline"
    );
    assert_eq!(pooled.pool_status().max_size, 1);
    drop(held);

    let poisoned = pooled.open_domain_session().await?;
    assert!(matches!(
        poisoned
            .run_operation(
                poisoned
                    .client()
                    .simple_query("SELECT registry_notary_api.pool_test_missing_function_v1()")
            )
            .await,
        Err(NotaryPostgresStatePlaneError::OperationUnavailable)
    ));
    drop(poisoned);
    drop(pooled.open_domain_session().await?);
    assert_eq!(
        pooled.created_session_count(),
        2,
        "a failed state operation must replace its physical session"
    );

    let rotated_url =
        format!("{runtime_url}&application_name=registry-notary-pool-generation-test");
    // SAFETY: this exact ignored test has exclusive process access to the
    // unique environment variable, as above.
    unsafe { std::env::set_var(POOL_DATABASE_URL_ENV, &rotated_url) };
    drop(pooled.open_domain_session().await?);
    assert_eq!(
        pooled.created_session_count(),
        3,
        "a URL generation change must evict and fully replace the old session"
    );

    let held = pooled.open_domain_session().await?;
    let waiter_runtime = Arc::clone(&pooled);
    let waiter =
        tokio::spawn(async move { waiter_runtime.open_domain_session().await.map(|_| ()) });
    tokio::time::timeout(Duration::from_secs(1), async {
        while pooled.pool_status().waiting != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    pooled.shutdown();
    assert!(matches!(
        waiter.await?,
        Err(NotaryPostgresStatePlaneError::Shutdown)
    ));
    drop(held);
    assert_eq!(
        pooled.readiness().await,
        NotaryPostgresStatePlaneReadiness::Shutdown
    );
    drop(pooled);
    // SAFETY: no runtime or concurrent test can read the unique variable
    // after the exact conformance test completes.
    unsafe { std::env::remove_var(POOL_DATABASE_URL_ENV) };
    Ok(())
}

const SUBJECT_ACCESS_QUOTA_CHECK_SQL: &str = "SELECT allowed, denied_bucket FROM \
     registry_notary_api.subject_access_quota_check_v1($1, $2, $3, $4)";
const SUBJECT_ACCESS_QUOTA_DEBIT_SQL: &str = "SELECT allowed, denied_bucket FROM \
     registry_notary_api.subject_access_quota_debit_v1($1, $2, $3, $4)";

async fn assert_replay_and_nonce_contracts(
    database_url: &str,
    runtime: &Client,
    admin: &Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let scope = vec![0x61_u8; 32];
    let replay_id = vec![0x62_u8; 32];
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::minutes(5);
    let (peer, peer_driver) = connect_as(database_url, RUNTIME_ROLE).await?;
    let (left, right) = tokio::join!(
        async {
            runtime
                .query_one(
                    "SELECT registry_notary_api.replay_insert_v1($1, $2, $3)",
                    &[&scope, &replay_id, &expires_at],
                )
                .await
        },
        async {
            peer.query_one(
                "SELECT registry_notary_api.replay_insert_v1($1, $2, $3)",
                &[&scope, &replay_id, &expires_at],
            )
            .await
        }
    );
    assert_eq!(
        [left?.get::<_, bool>(0), right?.get::<_, bool>(0)]
            .into_iter()
            .filter(|inserted| *inserted)
            .count(),
        1,
        "exactly one runtime may accept a replay identifier"
    );
    drop(peer);
    peer_driver.abort();

    let (restarted, restarted_driver) = connect_as(database_url, RUNTIME_ROLE).await?;
    assert!(!restarted
        .query_one(
            "SELECT registry_notary_api.replay_insert_v1($1, $2, $3)",
            &[&scope, &replay_id, &expires_at],
        )
        .await?
        .get::<_, bool>(0));
    admin
        .execute(
            "UPDATE registry_notary_private.replay_identifier SET \
             created_at = pg_catalog.clock_timestamp() - interval '2 seconds', \
             expires_at = \
             pg_catalog.clock_timestamp() - interval '1 second' \
             WHERE scope_hash = $1 AND identifier_hash = $2",
            &[&scope, &replay_id],
        )
        .await?;
    assert!(restarted
        .query_one(
            "SELECT registry_notary_api.replay_insert_v1($1, $2, $3)",
            &[&scope, &replay_id, &expires_at],
        )
        .await?
        .get::<_, bool>(0));
    drop(restarted);
    restarted_driver.abort();

    let nonce_scope = vec![0x63_u8; 32];
    let nonce = vec![0x64_u8; 32];
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.nonce_reserve_v1($1, $2, $3)",
            &[&nonce_scope, &nonce, &expires_at],
        )
        .await?
        .get::<_, bool>(0));
    let generation: i64 = runtime
        .query_one(
            "SELECT registry_notary_api.nonce_reservation_generation_v1($1, $2)",
            &[&nonce_scope, &nonce],
        )
        .await?
        .get(0);
    assert_eq!(generation, 1);
    let (peer, peer_driver) = connect_as(database_url, RUNTIME_ROLE).await?;
    let (left, right) = tokio::join!(
        async {
            runtime
                .query_one(
                    "SELECT registry_notary_api.nonce_consume_v1($1, $2, $3)",
                    &[&nonce_scope, &nonce, &generation],
                )
                .await
        },
        async {
            peer.query_one(
                "SELECT registry_notary_api.nonce_consume_v1($1, $2, $3)",
                &[&nonce_scope, &nonce, &generation],
            )
            .await
        }
    );
    assert_eq!(
        [left?.get::<_, bool>(0), right?.get::<_, bool>(0)]
            .into_iter()
            .filter(|consumed| *consumed)
            .count(),
        1,
        "a consumable nonce must have one winner"
    );
    let tombstone_seconds: f64 = admin
        .query_one(
            "SELECT EXTRACT(EPOCH FROM (tombstone_expires_at - updated_at))::double precision \
             FROM registry_notary_private.consumable_nonce \
             WHERE scope_hash = $1 AND nonce_hash = $2 AND state = 'consumed'",
            &[&nonce_scope, &nonce],
        )
        .await?
        .get(0);
    assert!((59.0..=61.0).contains(&tombstone_seconds));
    assert!(!runtime
        .query_one(
            "SELECT registry_notary_api.nonce_reserve_v1($1, $2, $3)",
            &[&nonce_scope, &nonce, &expires_at],
        )
        .await?
        .get::<_, bool>(0));
    admin
        .execute(
            "UPDATE registry_notary_private.consumable_nonce SET tombstone_expires_at = \
             pg_catalog.clock_timestamp() - interval '1 second' \
             WHERE scope_hash = $1 AND nonce_hash = $2",
            &[&nonce_scope, &nonce],
        )
        .await?;
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.nonce_reserve_v1($1, $2, $3)",
            &[&nonce_scope, &nonce, &expires_at],
        )
        .await?
        .get::<_, bool>(0));
    let replacement_generation: i64 = runtime
        .query_one(
            "SELECT registry_notary_api.nonce_reservation_generation_v1($1, $2)",
            &[&nonce_scope, &nonce],
        )
        .await?
        .get(0);
    assert_eq!(replacement_generation, generation + 1);
    assert!(!runtime
        .query_one(
            "SELECT registry_notary_api.nonce_consume_v1($1, $2, $3)",
            &[&nonce_scope, &nonce, &generation],
        )
        .await?
        .get::<_, bool>(0));
    admin
        .execute(
            "UPDATE registry_notary_private.consumable_nonce SET reservation_expires_at = \
             pg_catalog.clock_timestamp() - interval '1 second' \
             WHERE scope_hash = $1 AND nonce_hash = $2",
            &[&nonce_scope, &nonce],
        )
        .await?;
    assert!(!runtime
        .query_one(
            "SELECT registry_notary_api.nonce_consume_v1($1, $2, $3)",
            &[&nonce_scope, &nonce, &replacement_generation],
        )
        .await?
        .get::<_, bool>(0));
    drop(peer);
    peer_driver.abort();
    Ok(())
}

#[derive(Debug)]
struct BatchDecision {
    outcome: String,
    response_version: Option<i16>,
    response_json: Option<String>,
}

async fn batch_reserve(
    client: &Client,
    key: &[u8],
    request: &[u8],
    principal: &[u8],
    owner: &[u8],
    quota_limit: Option<i32>,
) -> Result<BatchDecision, tokio_postgres::Error> {
    let row = client
        .query_one(
            "SELECT outcome, response_version, response_json::text AS response_json FROM \
             registry_notary_api.batch_reserve_v1($1, $2, $3, $4, 30, $5, 1)",
            &[&key, &request, &principal, &owner, &quota_limit],
        )
        .await?;
    Ok(BatchDecision {
        outcome: row.get("outcome"),
        response_version: row.get("response_version"),
        response_json: row.get("response_json"),
    })
}

async fn assert_evaluation_and_batch_contracts(
    database_url: &str,
    runtime: &Client,
    admin: &Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let client_hash = vec![0x70_u8; 32];
    let request_hash = vec![0x71_u8; 32];
    let created_at = time::OffsetDateTime::now_utc();
    let expires_at = created_at + time::Duration::minutes(5);
    let created_at_json = created_at.format(&time::format_description::well_known::Rfc3339)?;
    let expires_at_json = expires_at.format(&time::format_description::well_known::Rfc3339)?;
    let record = serde_json::json!({"decision": "allow"});
    let record_json = record.to_string();
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.evaluation_insert_v1(\
             'evaluation-v1-rejected', $1, $2, 'conformance', 1::smallint, \
             $3::text::jsonb, $4, $5)",
            &[
                &client_hash,
                &request_hash,
                &record_json,
                &created_at,
                &expires_at
            ],
        )
        .await
        .is_err());
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.evaluation_insert_v1(\
             'evaluation-direct', $1, $2, 'conformance', 2::smallint, \
             $3::text::jsonb, $4, $5)",
            &[
                &client_hash,
                &request_hash,
                &record_json,
                &created_at,
                &expires_at
            ],
        )
        .await?
        .get::<_, bool>(0));
    assert!(!runtime
        .query_one(
            "SELECT registry_notary_api.evaluation_insert_v1(\
             'evaluation-direct', $1, $2, 'conformance', 2::smallint, \
             $3::text::jsonb, $4, $5)",
            &[
                &client_hash,
                &request_hash,
                &record_json,
                &created_at,
                &expires_at
            ],
        )
        .await?
        .get::<_, bool>(0));
    assert!(runtime
        .query_opt(
            "SELECT * FROM registry_notary_api.evaluation_get_v1('evaluation-direct', $1)",
            &[&client_hash],
        )
        .await?
        .is_some());
    assert!(runtime
        .query_opt(
            "SELECT * FROM registry_notary_api.evaluation_get_v1('evaluation-direct', $1)",
            &[&vec![0x72_u8; 32]],
        )
        .await?
        .is_none());
    admin
        .execute(
            "UPDATE registry_notary_private.evaluation SET expires_at = \
             pg_catalog.clock_timestamp() - interval '1 second', created_at = \
             pg_catalog.clock_timestamp() - interval '2 seconds' \
             WHERE evaluation_id = 'evaluation-direct'",
            &[],
        )
        .await?;
    assert!(runtime
        .query_opt(
            "SELECT * FROM registry_notary_api.evaluation_get_v1('evaluation-direct', $1)",
            &[&client_hash],
        )
        .await?
        .is_none());

    let key = vec![0x73_u8; 32];
    let request = vec![0x74_u8; 32];
    let other_request = vec![0x75_u8; 32];
    let principal = vec![0x76_u8; 32];
    let owner_a = vec![0x77_u8; 32];
    let owner_b = vec![0x78_u8; 32];
    assert_eq!(
        batch_reserve(runtime, &key, &request, &principal, &owner_a, Some(2))
            .await?
            .outcome,
        "owner"
    );
    assert_eq!(
        batch_reserve(runtime, &key, &request, &principal, &owner_b, Some(2))
            .await?
            .outcome,
        "wait"
    );
    assert_eq!(
        batch_reserve(runtime, &key, &other_request, &principal, &owner_b, Some(2),)
            .await?
            .outcome,
        "conflict"
    );
    assert!(!runtime
        .query_one(
            "SELECT registry_notary_api.batch_heartbeat_v1($1, $2, $3, 30)",
            &[&key, &request, &owner_b],
        )
        .await?
        .get::<_, bool>(0));
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.batch_heartbeat_v1($1, $2, $3, 30)",
            &[&key, &request, &owner_a],
        )
        .await?
        .get::<_, bool>(0));
    admin
        .execute(
            "UPDATE registry_notary_private.batch_idempotency SET lease_expires_at = \
             pg_catalog.clock_timestamp() - interval '1 second' WHERE key_hash = $1",
            &[&key],
        )
        .await?;
    assert_eq!(
        batch_reserve(runtime, &key, &request, &principal, &owner_b, Some(2))
            .await?
            .outcome,
        "owner"
    );
    let quota_row = runtime
        .query_one(
            "SELECT allowed, remaining FROM \
             registry_notary_api.machine_quota_debit_v1($1, 2, 1)",
            &[&principal],
        )
        .await?;
    assert!(quota_row.get::<_, bool>("allowed"));
    assert_eq!(quota_row.get::<_, i32>("remaining"), 0);
    assert!(!runtime
        .query_one(
            "SELECT allowed FROM registry_notary_api.machine_quota_debit_v1($1, 2, 1)",
            &[&principal],
        )
        .await?
        .get::<_, bool>(0));

    let evaluations = serde_json::json!([{
        "evaluation_id": "evaluation-batch",
        "client_id_hash_hex": "7979797979797979797979797979797979797979797979797979797979797979",
        "purpose": "conformance",
        "record_version": 2,
        "record": {"decision": "allow"},
        "created_at": created_at_json,
        "expires_at": expires_at_json
    }]);
    let invalid_evaluations = serde_json::json!([
        evaluations[0].clone(),
        {
            "evaluation_id": "evaluation-batch-invalid",
            "client_id_hash_hex": "7979797979797979797979797979797979797979797979797979797979797979",
            "purpose": "conformance",
            "record_version": 1,
            "record": {"decision": "deny"},
            "created_at": created_at_json,
            "expires_at": expires_at_json
        }
    ]);
    let response = serde_json::json!({"batch_id": "batch-conformance"});
    let evaluations_json = evaluations.to_string();
    let invalid_evaluations_json = invalid_evaluations.to_string();
    let response_json = response.to_string();
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.batch_complete_v1(\
             $1, $2, $3, $4::text::jsonb, 1::smallint, $5::text::jsonb)",
            &[&key, &request, &owner_b, &evaluations_json, &response_json],
        )
        .await
        .is_err());
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.batch_complete_v1(\
             $1, $2, $3, $4::text::jsonb, 2::smallint, $5::text::jsonb)",
            &[
                &key,
                &request,
                &owner_b,
                &invalid_evaluations_json,
                &response_json
            ],
        )
        .await
        .is_err());
    assert!(runtime
        .query_opt(
            "SELECT * FROM registry_notary_api.evaluation_get_v1('evaluation-batch', $1)",
            &[&vec![0x79_u8; 32]],
        )
        .await?
        .is_none());
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.batch_complete_v1(\
             $1, $2, $3, $4::text::jsonb, 2::smallint, $5::text::jsonb)",
            &[&key, &request, &owner_b, &evaluations_json, &response_json],
        )
        .await?
        .get::<_, bool>(0));
    assert!(runtime
        .query_opt(
            "SELECT * FROM registry_notary_api.evaluation_get_v1('evaluation-batch', $1)",
            &[&vec![0x79_u8; 32]],
        )
        .await?
        .is_some());
    let replay = batch_reserve(runtime, &key, &request, &principal, &owner_a, Some(2)).await?;
    assert_eq!(replay.outcome, "replay");
    assert_eq!(replay.response_version, Some(2));
    assert_eq!(
        replay
            .response_json
            .as_deref()
            .map(serde_json::from_str::<serde_json::Value>)
            .transpose()?,
        Some(response)
    );

    let failed_key = vec![0x7a_u8; 32];
    assert_eq!(
        batch_reserve(runtime, &failed_key, &request, &principal, &owner_a, None,)
            .await?
            .outcome,
        "owner"
    );
    assert!(!runtime
        .query_one(
            "SELECT registry_notary_api.batch_fail_v1($1, $2, $3)",
            &[&failed_key, &request, &owner_b],
        )
        .await?
        .get::<_, bool>(0));
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.batch_fail_v1($1, $2, $3)",
            &[&failed_key, &request, &owner_a],
        )
        .await?
        .get::<_, bool>(0));
    let (peer, peer_driver) = connect_as(database_url, RUNTIME_ROLE).await?;
    assert_eq!(
        batch_reserve(&peer, &failed_key, &request, &principal, &owner_b, None)
            .await?
            .outcome,
        "owner"
    );
    drop(peer);
    peer_driver.abort();
    Ok(())
}

async fn assert_credential_status_and_machine_quota_contracts(
    database_url: &str,
    runtime: &Client,
    admin: &Client,
) -> Result<(), Box<dyn std::error::Error>> {
    // A Notary instance clock may lead the database clock slightly. Status
    // transitions must remain valid and monotonic across that skew.
    let issued_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(5);
    let credential_expires_at = issued_at + time::Duration::hours(1);
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.credential_status_insert_v1(\
             'credential-concurrent', 'issuer', 'profile', $1, $2, 3600)",
            &[&issued_at, &credential_expires_at],
        )
        .await?
        .get::<_, bool>(0));
    assert!(!runtime
        .query_one(
            "SELECT registry_notary_api.credential_status_insert_v1(\
             'credential-concurrent', 'issuer', 'profile', $1, $2, 3600)",
            &[&issued_at, &credential_expires_at],
        )
        .await?
        .get::<_, bool>(0));
    assert_eq!(
        runtime
            .query_one(
                "SELECT status FROM registry_notary_api.credential_status_get_v1(\
                 'credential-concurrent')",
                &[],
            )
            .await?
            .get::<_, String>(0),
        "valid"
    );
    let (peer, peer_driver) = connect_as(database_url, RUNTIME_ROLE).await?;
    let (suspended, revoked) = tokio::join!(
        runtime.query_one(
            "SELECT outcome FROM registry_notary_api.credential_status_update_v1(\
             'credential-concurrent', 'suspended')",
            &[],
        ),
        peer.query_one(
            "SELECT outcome FROM registry_notary_api.credential_status_update_v1(\
             'credential-concurrent', 'revoked')",
            &[],
        )
    );
    let suspended = suspended?.get::<_, String>(0);
    let revoked = revoked?.get::<_, String>(0);
    assert_eq!(revoked, "updated");
    assert!(matches!(
        suspended.as_str(),
        "updated" | "invalid_transition"
    ));
    assert_eq!(
        runtime
            .query_one(
                "SELECT status FROM registry_notary_api.credential_status_get_v1(\
                 'credential-concurrent')",
                &[],
            )
            .await?
            .get::<_, String>(0),
        "revoked"
    );
    assert_eq!(
        runtime
            .query_one(
                "SELECT outcome FROM registry_notary_api.credential_status_update_v1(\
                 'credential-concurrent', 'valid')",
                &[],
            )
            .await?
            .get::<_, String>(0),
        "invalid_transition"
    );
    drop(peer);
    peer_driver.abort();

    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.credential_status_insert_v1(\
             'credential-expired', 'issuer', 'profile', \
             pg_catalog.clock_timestamp() - interval '2 hours', \
             pg_catalog.clock_timestamp() - interval '1 hour', 7200)",
            &[],
        )
        .await?
        .get::<_, bool>(0));
    let expired_row = runtime
        .query_one(
            "SELECT * FROM registry_notary_api.credential_status_get_v1('credential-expired')",
            &[],
        )
        .await?;
    assert_eq!(expired_row.get::<_, String>("status"), "valid");
    assert_eq!(
        expired_row.get::<_, String>("effective_status"),
        "expired",
        "PostgreSQL time must derive expiry independently of replica clocks"
    );
    let expired_record = crate::credential_status::postgres_status_record(&expired_row)?;
    assert_eq!(
        expired_record.effective_status(time::OffsetDateTime::UNIX_EPOCH),
        registry_notary_core::CREDENTIAL_STATUS_EXPIRED,
        "a replica clock far behind PostgreSQL must not reopen an expired credential"
    );
    let expired_suspended_row = runtime
        .query_one(
            "SELECT * FROM registry_notary_api.credential_status_update_v1(\
             'credential-expired', 'suspended')",
            &[],
        )
        .await?;
    assert_eq!(expired_suspended_row.get::<_, String>("outcome"), "updated");
    assert_eq!(
        expired_suspended_row.get::<_, String>("status"),
        "suspended"
    );
    assert_eq!(
        expired_suspended_row.get::<_, String>("effective_status"),
        "expired",
        "credential expiry must supersede a stored suspension"
    );
    let expired_suspended_record =
        crate::credential_status::postgres_status_record(&expired_suspended_row)?;
    assert_eq!(
        expired_suspended_record.effective_status(time::OffsetDateTime::UNIX_EPOCH),
        registry_notary_core::CREDENTIAL_STATUS_EXPIRED
    );
    admin
        .execute(
            "UPDATE registry_notary_private.credential_status SET \
             issued_at = pg_catalog.clock_timestamp() - interval '3 hours', \
             credential_expires_at = pg_catalog.clock_timestamp() - interval '2 hours', \
             updated_at = pg_catalog.clock_timestamp() - interval '2 hours', \
             purge_after = pg_catalog.clock_timestamp() - interval '1 hour' \
             WHERE credential_id = 'credential-expired'",
            &[],
        )
        .await?;
    assert!(runtime
        .query_opt(
            "SELECT * FROM registry_notary_api.credential_status_get_v1('credential-expired')",
            &[],
        )
        .await?
        .is_none());

    let principal = vec![0x80_u8; 32];
    let first = runtime
        .query_one(
            "SELECT allowed, remaining, retry_after_seconds FROM \
             registry_notary_api.machine_quota_debit_v1($1, 3, 2)",
            &[&principal],
        )
        .await?;
    assert!(first.get::<_, bool>("allowed"));
    assert_eq!(first.get::<_, i32>("remaining"), 1);
    assert_eq!(first.get::<_, i64>("retry_after_seconds"), 0);
    let boundary = runtime
        .query_one(
            "SELECT allowed, remaining FROM \
             registry_notary_api.machine_quota_debit_v1($1, 3, 1)",
            &[&principal],
        )
        .await?;
    assert!(boundary.get::<_, bool>("allowed"));
    assert_eq!(boundary.get::<_, i32>("remaining"), 0);
    let denied = runtime
        .query_one(
            "SELECT allowed, remaining, retry_after_seconds FROM \
             registry_notary_api.machine_quota_debit_v1($1, 3, 1)",
            &[&principal],
        )
        .await?;
    assert!(!denied.get::<_, bool>("allowed"));
    assert_eq!(denied.get::<_, i32>("remaining"), 0);
    assert!(denied.get::<_, i64>("retry_after_seconds") >= 1);

    let once_principal = vec![0x86_u8; 32];
    let exact_operation = vec![0x87_u8; 32];
    let distinct_operation = vec![0x88_u8; 32];
    let exact_request = vec![0x8b_u8; 32];
    let first_owner = vec![0x89_u8; 32];
    let takeover_owner = vec![0x8a_u8; 32];
    let operation_expires_at = time::OffsetDateTime::now_utc() + time::Duration::minutes(10);
    let (quota_peer, quota_peer_driver) = connect_as(database_url, RUNTIME_ROLE).await?;
    let first_args: [&(dyn tokio_postgres::types::ToSql + Sync); 5] = [
        &once_principal,
        &exact_operation,
        &exact_request,
        &first_owner,
        &operation_expires_at,
    ];
    let retry_args: [&(dyn tokio_postgres::types::ToSql + Sync); 5] = [
        &once_principal,
        &exact_operation,
        &exact_request,
        &takeover_owner,
        &operation_expires_at,
    ];
    let (first, exact_retry) = tokio::join!(
        runtime.query_one(
            "SELECT allowed, acquired, remaining FROM \
             registry_notary_api.machine_quota_debit_once_v1(\
                 $1, $2, $3, $4, 1, 1, 60, $5)",
            &first_args,
        ),
        quota_peer.query_one(
            "SELECT allowed, acquired, remaining FROM \
             registry_notary_api.machine_quota_debit_once_v1(\
                 $1, $2, $3, $4, 1, 1, 60, $5)",
            &retry_args,
        ),
    );
    let first = first?;
    let exact_retry = exact_retry?;
    assert!(first.get::<_, bool>("allowed"));
    assert_eq!(first.get::<_, i32>("remaining"), 0);
    assert!(exact_retry.get::<_, bool>("allowed"));
    assert_eq!(exact_retry.get::<_, i32>("remaining"), 0);
    let first_acquired = first.get::<_, bool>("acquired");
    let retry_acquired = exact_retry.get::<_, bool>("acquired");
    assert_ne!(
        first_acquired, retry_acquired,
        "exact operations racing on separate connections have one lease owner"
    );
    let (acquired_owner, waiting_owner) = if first_acquired {
        (&first_owner, &takeover_owner)
    } else {
        (&takeover_owner, &first_owner)
    };
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.machine_quota_operation_release_v1($1, $2, $3)",
            &[&once_principal, &exact_operation, acquired_owner],
        )
        .await?
        .get::<_, bool>(0));
    let takeover = runtime
        .query_one(
            "SELECT allowed, acquired, remaining FROM \
             registry_notary_api.machine_quota_debit_once_v1(\
                 $1, $2, $3, $4, 1, 1, 60, $5)",
            &[
                &once_principal,
                &exact_operation,
                &exact_request,
                waiting_owner,
                &operation_expires_at,
            ],
        )
        .await?;
    assert!(takeover.get::<_, bool>("allowed"));
    assert!(takeover.get::<_, bool>("acquired"));
    assert_eq!(takeover.get::<_, i32>("remaining"), 0);
    assert!(!runtime
        .query_one(
            "SELECT allowed FROM \
             registry_notary_api.machine_quota_debit_once_v1(\
                 $1, $2, $3, $4, 1, 1, 60, $5)",
            &[
                &once_principal,
                &distinct_operation,
                &exact_request,
                &takeover_owner,
                &operation_expires_at,
            ],
        )
        .await?
        .get::<_, bool>("allowed"));

    let conflict_principal = vec![0x8c_u8; 32];
    let conflict_operation = vec![0x8d_u8; 32];
    let request_a = vec![0x8e_u8; 32];
    let request_b = vec![0x8f_u8; 32];
    let conflict_a_args: [&(dyn tokio_postgres::types::ToSql + Sync); 5] = [
        &conflict_principal,
        &conflict_operation,
        &request_a,
        &first_owner,
        &operation_expires_at,
    ];
    let conflict_b_args: [&(dyn tokio_postgres::types::ToSql + Sync); 5] = [
        &conflict_principal,
        &conflict_operation,
        &request_b,
        &takeover_owner,
        &operation_expires_at,
    ];
    let conflict_a = runtime.query_one(
        "SELECT allowed, acquired, conflict FROM \
         registry_notary_api.machine_quota_debit_once_v1(\
             $1, $2, $3, $4, 2, 1, 60, $5)",
        &conflict_a_args,
    );
    let conflict_b = quota_peer.query_one(
        "SELECT allowed, acquired, conflict FROM \
         registry_notary_api.machine_quota_debit_once_v1(\
             $1, $2, $3, $4, 2, 1, 60, $5)",
        &conflict_b_args,
    );
    let (conflict_a, conflict_b) = tokio::join!(conflict_a, conflict_b);
    let conflict_a = conflict_a?;
    let conflict_b = conflict_b?;
    assert!(conflict_a.get::<_, bool>("allowed"));
    assert!(conflict_b.get::<_, bool>("allowed"));
    assert_eq!(
        [
            conflict_a.get::<_, bool>("acquired"),
            conflict_b.get::<_, bool>("acquired"),
        ]
        .into_iter()
        .filter(|acquired| *acquired)
        .count(),
        1,
    );
    assert_eq!(
        [
            conflict_a.get::<_, bool>("conflict"),
            conflict_b.get::<_, bool>("conflict"),
        ]
        .into_iter()
        .filter(|conflict| *conflict)
        .count(),
        1,
    );
    assert_eq!(
        admin
            .query_one(
                "SELECT used FROM registry_notary_private.machine_quota \
                 WHERE principal_hash = $1",
                &[&conflict_principal],
            )
            .await?
            .get::<_, i32>("used"),
        1,
        "request-shape conflict must not debit the idempotency operation twice",
    );

    let disabled_principal = vec![0x90_u8; 32];
    let disabled_operation = vec![0x91_u8; 32];
    let disabled_request = vec![0x92_u8; 32];
    let disabled_first = runtime
        .query_one(
            "SELECT acquired FROM registry_notary_api.machine_quota_debit_once_v1(\
                 $1, $2, $3, $4, NULL::integer, 1, 60, $5)",
            &[
                &disabled_principal,
                &disabled_operation,
                &disabled_request,
                &first_owner,
                &operation_expires_at,
            ],
        )
        .await?;
    assert!(disabled_first.get::<_, bool>("acquired"));
    let disabled_retry = quota_peer
        .query_one(
            "SELECT acquired, conflict FROM \
             registry_notary_api.machine_quota_debit_once_v1(\
                 $1, $2, $3, $4, NULL::integer, 1, 60, $5)",
            &[
                &disabled_principal,
                &disabled_operation,
                &disabled_request,
                &takeover_owner,
                &operation_expires_at,
            ],
        )
        .await?;
    assert!(!disabled_retry.get::<_, bool>("acquired"));
    assert!(!disabled_retry.get::<_, bool>("conflict"));
    assert_eq!(
        admin
            .query_one(
                "SELECT used FROM registry_notary_private.machine_quota \
                 WHERE principal_hash = $1",
                &[&disabled_principal],
            )
            .await?
            .get::<_, i32>("used"),
        0,
        "disabled quota retains ownership without charging budget",
    );
    drop(quota_peer);
    quota_peer_driver.abort();
    Ok(())
}

async fn assert_preauthorization_contracts(
    database_url: &str,
    runtime: &Client,
    admin: &Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = vec![0x81_u8; 32];
    let key_id = vec![0x82_u8; 32];
    let nonce = vec![0x83_u8; 12];
    let ciphertext = vec![0x84_u8; 17];
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::days(1);
    let reserve_login_sql = "SELECT registry_notary_api.\
         preauthorization_login_reserve_v1($1, 'credential-config', $2, $3, $4, $5)";
    assert_eq!(
        runtime
            .query_one(
                reserve_login_sql,
                &[&state, &key_id, &nonce, &ciphertext, &expires_at],
            )
            .await?
            .get::<_, i16>(0),
        1
    );
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.preauthorization_key_attest_v1($1)",
            &[&key_id],
        )
        .await?
        .get::<_, bool>(0));
    assert!(!runtime
        .query_one(
            "SELECT registry_notary_api.preauthorization_key_attest_v1($1)",
            &[&vec![0x8f_u8; 32]],
        )
        .await?
        .get::<_, bool>(0));
    assert_eq!(
        runtime
            .query_one(
                reserve_login_sql,
                &[&state, &key_id, &nonce, &ciphertext, &expires_at],
            )
            .await?
            .get::<_, i16>(0),
        0
    );
    let (peer, peer_driver) = connect_as(database_url, RUNTIME_ROLE).await?;
    let (left, right) = tokio::join!(
        async {
            runtime
                .query_opt(
                    "SELECT * FROM registry_notary_api.\
                     preauthorization_login_consume_v1($1)",
                    &[&state],
                )
                .await
        },
        async {
            peer.query_opt(
                "SELECT * FROM registry_notary_api.\
                 preauthorization_login_consume_v1($1)",
                &[&state],
            )
            .await
        }
    );
    assert_eq!(
        [left?.is_some(), right?.is_some()]
            .into_iter()
            .filter(|consumed| *consumed)
            .count(),
        1
    );
    assert_eq!(
        runtime
            .query_one(
                reserve_login_sql,
                &[&state, &key_id, &nonce, &ciphertext, &expires_at],
            )
            .await?
            .get::<_, i16>(0),
        1
    );
    admin
        .execute(
            "UPDATE registry_notary_private.preauthorization_login_state SET \
             created_at = pg_catalog.clock_timestamp() - interval '2 seconds', \
             expires_at = pg_catalog.clock_timestamp() - interval '1 second' \
             WHERE state_hash = $1",
            &[&state],
        )
        .await?;
    assert!(runtime
        .query_opt(
            "SELECT * FROM registry_notary_api.preauthorization_login_consume_v1($1)",
            &[&state],
        )
        .await?
        .is_none());

    admin
        .execute(
            "DELETE FROM registry_notary_private.preauthorization_login_state",
            &[],
        )
        .await?;
    admin
        .execute(
            "INSERT INTO registry_notary_private.preauthorization_login_state (\
             state_hash, credential_configuration_id, key_id, aead_nonce, ciphertext, \
             created_at, expires_at) SELECT pg_catalog.decode(\
             pg_catalog.lpad(pg_catalog.to_hex(value), 64, '0'), 'hex'), \
             'credential-config', $1, $2, $3, pg_catalog.clock_timestamp(), \
             pg_catalog.clock_timestamp() + interval '5 minutes' \
             FROM pg_catalog.generate_series(1, 4096) AS value",
            &[&key_id, &nonce, &ciphertext],
        )
        .await?;
    let capacity_state = vec![0xfe_u8; 32];
    assert_eq!(
        runtime
            .query_one(
                reserve_login_sql,
                &[&capacity_state, &key_id, &nonce, &ciphertext, &expires_at],
            )
            .await?
            .get::<_, i16>(0),
        -1
    );
    admin
        .execute(
            "UPDATE registry_notary_private.preauthorization_login_state SET \
             created_at = pg_catalog.clock_timestamp() - interval '2 seconds', \
             expires_at = pg_catalog.clock_timestamp() - interval '1 second' \
             WHERE state_hash = pg_catalog.decode(\
             pg_catalog.lpad(pg_catalog.to_hex(1), 64, '0'), 'hex')",
            &[],
        )
        .await?;
    assert_eq!(
        runtime
            .query_one(
                reserve_login_sql,
                &[&capacity_state, &key_id, &nonce, &ciphertext, &expires_at],
            )
            .await?
            .get::<_, i16>(0),
        1
    );
    admin
        .execute(
            "DELETE FROM registry_notary_private.preauthorization_login_state",
            &[],
        )
        .await?;

    let competing_key_id = vec![0x8f_u8; 32];
    let competing_state = vec![0x8d_u8; 32];
    let competing_jti = vec![0x8e_u8; 32];
    let competing_pin = vec![0x8c_u8; 32];
    let (first_generation, second_generation) = tokio::join!(
        async {
            runtime
                .query_one(
                    reserve_login_sql,
                    &[&competing_state, &key_id, &nonce, &ciphertext, &expires_at],
                )
                .await
        },
        async {
            peer.query_one(
                "SELECT registry_notary_api.preauthorization_tx_code_reserve_v1(\
                 $1, $2, $3, 6::smallint, $4)",
                &[
                    &competing_jti,
                    &competing_key_id,
                    &competing_pin,
                    &expires_at,
                ],
            )
            .await
        }
    );
    assert_eq!(
        [first_generation.is_ok(), second_generation.is_ok()]
            .into_iter()
            .filter(|accepted| *accepted)
            .count(),
        1,
        "different sensitive-key generations must not create mixed live state"
    );
    let live_key_generations: i64 = admin
        .query_one(
            "SELECT count(DISTINCT encode(key_id, 'hex')) FROM ( \
               SELECT key_id FROM registry_notary_private.preauthorization_login_state \
                WHERE expires_at > pg_catalog.clock_timestamp() \
               UNION ALL \
               SELECT key_id FROM registry_notary_private.preauthorization_tx_code \
                WHERE expires_at > pg_catalog.clock_timestamp() \
             ) AS live_sensitive_state",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(live_key_generations, 1);
    admin
        .batch_execute(
            "UPDATE registry_notary_private.preauthorization_login_state \
                SET created_at = pg_catalog.clock_timestamp() - interval '2 seconds', \
                    expires_at = pg_catalog.clock_timestamp() - interval '1 second'; \
             UPDATE registry_notary_private.preauthorization_tx_code \
                SET created_at = pg_catalog.clock_timestamp() - interval '2 seconds', \
                    expires_at = pg_catalog.clock_timestamp() - interval '1 second';",
        )
        .await?;
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.preauthorization_tx_code_reserve_v1(\
             $1, $2, $3, 6::smallint, $4)",
            &[
                &competing_jti,
                &competing_key_id,
                &competing_pin,
                &expires_at,
            ],
        )
        .await?
        .get::<_, bool>(0));
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.preauthorization_key_attest_v1($1)",
            &[&competing_key_id],
        )
        .await?
        .get::<_, bool>(0));
    admin
        .batch_execute(
            "DELETE FROM registry_notary_private.preauthorization_login_state; \
             DELETE FROM registry_notary_private.preauthorization_tx_code;",
        )
        .await?;

    let jti = vec![0x85_u8; 32];
    let pin = vec![0x86_u8; 32];
    let wrong_pin = vec![0x87_u8; 32];
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.preauthorization_tx_code_reserve_v1(\
             $1, $2, $3, 6::smallint, $4)",
            &[&jti, &key_id, &pin, &expires_at],
        )
        .await?
        .get::<_, bool>(0));
    assert!(!runtime
        .query_one(
            "SELECT registry_notary_api.preauthorization_tx_code_reserve_v1(\
             $1, $2, $3, 6::smallint, $4)",
            &[&jti, &key_id, &pin, &expires_at],
        )
        .await?
        .get::<_, bool>(0));
    let peek = runtime
        .query_one(
            "SELECT key_id, pin_verifier, pin_length FROM \
             registry_notary_api.preauthorization_tx_code_peek_v1($1)",
            &[&jti],
        )
        .await?;
    assert_eq!(peek.get::<_, Vec<u8>>("key_id"), key_id);
    assert_eq!(peek.get::<_, Vec<u8>>("pin_verifier"), pin);
    assert_eq!(peek.get::<_, i16>("pin_length"), 6);
    let replay_scope = vec![0x88_u8; 32];
    assert!(!runtime
        .query_one(
            "SELECT registry_notary_api.preauthorization_redeem_v1(\
             $1, $2, $3, TRUE, $4)",
            &[&replay_scope, &jti, &expires_at, &wrong_pin],
        )
        .await?
        .get::<_, bool>(0));
    assert!(runtime
        .query_opt(
            "SELECT * FROM registry_notary_api.preauthorization_tx_code_peek_v1($1)",
            &[&jti],
        )
        .await?
        .is_some());
    let (left, right) = tokio::join!(
        async {
            runtime
                .query_one(
                    "SELECT registry_notary_api.preauthorization_redeem_v1(\
                     $1, $2, $3, TRUE, $4)",
                    &[&replay_scope, &jti, &expires_at, &pin],
                )
                .await
        },
        async {
            peer.query_one(
                "SELECT registry_notary_api.preauthorization_redeem_v1(\
                 $1, $2, $3, TRUE, $4)",
                &[&replay_scope, &jti, &expires_at, &pin],
            )
            .await
        }
    );
    assert_eq!(
        [left?.get::<_, bool>(0), right?.get::<_, bool>(0)]
            .into_iter()
            .filter(|redeemed| *redeemed)
            .count(),
        1
    );
    assert!(runtime
        .query_opt(
            "SELECT * FROM registry_notary_api.preauthorization_tx_code_peek_v1($1)",
            &[&jti],
        )
        .await?
        .is_none());
    assert!(!runtime
        .query_one(
            "SELECT registry_notary_api.preauthorization_redeem_v1(\
             $1, $2, $3, TRUE, $4)",
            &[&replay_scope, &jti, &expires_at, &pin],
        )
        .await?
        .get::<_, bool>(0));

    let expired_jti = vec![0x89_u8; 32];
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.preauthorization_tx_code_reserve_v1(\
             $1, $2, $3, 6::smallint, $4)",
            &[&expired_jti, &key_id, &pin, &expires_at],
        )
        .await?
        .get::<_, bool>(0));
    admin
        .execute(
            "UPDATE registry_notary_private.preauthorization_tx_code SET \
             created_at = pg_catalog.clock_timestamp() - interval '2 seconds', \
             expires_at = pg_catalog.clock_timestamp() - interval '1 second' \
             WHERE jti_hash = $1",
            &[&expired_jti],
        )
        .await?;
    assert!(runtime
        .query_opt(
            "SELECT * FROM registry_notary_api.preauthorization_tx_code_peek_v1($1)",
            &[&expired_jti],
        )
        .await?
        .is_none());
    assert!(!runtime
        .query_one(
            "SELECT registry_notary_api.preauthorization_redeem_v1(\
             $1, $2, $3, TRUE, $4)",
            &[&replay_scope, &expired_jti, &expires_at, &pin],
        )
        .await?
        .get::<_, bool>(0));
    assert!(runtime
        .query_one(
            "SELECT registry_notary_api.preauthorization_tx_code_reserve_v1(\
             $1, $2, $3, 6::smallint, $4)",
            &[&expired_jti, &key_id, &pin, &expires_at],
        )
        .await?
        .get::<_, bool>(0));
    admin
        .batch_execute(
            "DELETE FROM registry_notary_private.preauthorization_login_state; \
             DELETE FROM registry_notary_private.preauthorization_tx_code;",
        )
        .await?;
    drop(peer);
    peer_driver.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires an installed Notary PostgreSQL state plane"]
async fn postgres_v1_sensitive_restart_restore_probe() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::var(SENSITIVE_PROBE_MODE_ENV)?;
    let probe_pin = std::env::var(SENSITIVE_PROBE_PIN_ENV)?;
    if probe_pin.len() != 6 || !probe_pin.bytes().all(|value| value.is_ascii_uppercase()) {
        return Err("restart probe PIN is invalid".into());
    }
    let config = PostgresStatePlaneConfig::new(
        SENSITIVE_DATABASE_URL_ENV,
        Some(PathBuf::from(std::env::var(DATABASE_CA_ENV)?)),
        Duration::from_secs(2),
        Duration::from_secs(2),
        1,
    )?;
    let runtime = Arc::new(NotaryPostgresStatePlaneRuntime::connect(&config).await?);
    let sensitive = PostgresSensitiveState::activate(
        Arc::clone(&runtime),
        &SensitiveStateKeyConfig::new(SENSITIVE_KEY_ENV)?,
    )
    .await?;
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::minutes(9);

    if mode == "seed" {
        for phase in ["process", "database", "restore"] {
            let login = LoginState {
                pkce_verifier: format!("restart-{phase}-pkce-secret"),
                nonce: format!("restart-{phase}-login-nonce"),
                credential_configuration_id: format!("restart-{phase}-config"),
                representative: None,
                csrf_token: None,
            };
            assert_eq!(
                sensitive
                    .reserve_login(&format!("restart-{phase}-opaque-state"), &login, expires_at)
                    .await?,
                LoginReserveOutcome::Reserved
            );
            assert!(
                sensitive
                    .reserve_transaction_code(
                        &format!("restart-{phase}-jti"),
                        &probe_pin,
                        6,
                        expires_at,
                    )
                    .await?
            );
            let replay_scope = registry_platform_replay::ReplayScope::new([(
                "flow",
                format!("restart-{phase}-spent-preauthorization"),
            )])?;
            assert!(
                sensitive
                    .redeem(
                        &replay_scope,
                        &format!("restart-{phase}-spent-jti"),
                        expires_at,
                        None,
                    )
                    .await?,
                "seed must persist a spent no-PIN preauthorization code"
            );
        }
    } else if matches!(mode.as_str(), "process" | "database" | "restore") {
        let login = sensitive
            .consume_login(&format!("restart-{mode}-opaque-state"))
            .await?
            .ok_or("restart probe login state is unavailable")?;
        if login.pkce_verifier != format!("restart-{mode}-pkce-secret")
            || login.nonce != format!("restart-{mode}-login-nonce")
            || login.credential_configuration_id != format!("restart-{mode}-config")
        {
            return Err("restart probe login state did not decrypt exactly".into());
        }
        let jti = format!("restart-{mode}-jti");
        let proof = sensitive
            .verify_transaction_code(&jti, &probe_pin)
            .await?
            .ok_or("restart probe transaction-code verifier is unavailable")?;
        let scope = registry_platform_replay::ReplayScope::new([("flow", mode.as_str())])?;
        if !sensitive
            .redeem(&scope, &jti, expires_at, Some(proof))
            .await?
        {
            return Err("restart probe transaction code was not redeemable".into());
        }
        let replay_scope = registry_platform_replay::ReplayScope::new([(
            "flow",
            format!("restart-{mode}-spent-preauthorization"),
        )])?;
        if sensitive
            .redeem(
                &replay_scope,
                &format!("restart-{mode}-spent-jti"),
                expires_at,
                None,
            )
            .await?
        {
            return Err("restart or restore reopened a spent no-PIN preauthorization code".into());
        }
    } else {
        return Err("restart probe mode is invalid".into());
    }

    runtime.shutdown();
    Ok(())
}

async fn assert_sensitive_adapter_contract(
    database_url: &str,
    admin: &Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime_url = database_url.replacen("postgres@", &format!("{RUNTIME_ROLE}@"), 1);
    if runtime_url == database_url {
        return Err("sensitive adapter URL does not contain the dedicated admin role".into());
    }
    let primary_key = URL_SAFE_NO_PAD.encode([0xa1_u8; 32]);
    let wrong_key = URL_SAFE_NO_PAD.encode([0xb2_u8; 32]);
    // SAFETY: the conformance harness runs this ignored test by exact name
    // in an isolated process, so these dedicated variables have no readers.
    unsafe {
        std::env::set_var(SENSITIVE_DATABASE_URL_ENV, &runtime_url);
        std::env::remove_var(SENSITIVE_KEY_ENV);
    }
    let config = PostgresStatePlaneConfig::new(
        SENSITIVE_DATABASE_URL_ENV,
        Some(PathBuf::from(std::env::var(DATABASE_CA_ENV)?)),
        Duration::from_secs(2),
        Duration::from_secs(2),
        2,
    )?;
    let runtime = Arc::new(NotaryPostgresStatePlaneRuntime::connect(&config).await?);
    let key_config = SensitiveStateKeyConfig::new(SENSITIVE_KEY_ENV)?;
    let missing_key_error = PostgresSensitiveState::activate(Arc::clone(&runtime), &key_config)
        .await
        .expect_err("an absent sensitive-state key must fail activation");
    assert_eq!(
        missing_key_error,
        SensitiveStateError::KeyEnvironmentUnavailable
    );
    assert_eq!(
        missing_key_error.to_string(),
        "Notary sensitive-state key environment variable is unavailable"
    );
    let rendered_error = format!("{missing_key_error:?}");
    assert!(!rendered_error.contains(SENSITIVE_KEY_ENV));
    assert!(!rendered_error.contains(&primary_key));
    assert!(!rendered_error.contains(&wrong_key));

    // SAFETY: this exact-name live test remains isolated from other
    // environment readers for its entire process lifetime.
    unsafe { std::env::set_var(SENSITIVE_KEY_ENV, &primary_key) };
    let sensitive = PostgresSensitiveState::activate(Arc::clone(&runtime), &key_config).await?;
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let login = LoginState {
        pkce_verifier: "adapter-pkce-secret".to_string(),
        nonce: "adapter-login-nonce".to_string(),
        credential_configuration_id: "adapter-config".to_string(),
        representative: None,
        csrf_token: None,
    };
    assert_eq!(
        sensitive
            .reserve_login("adapter-opaque-state", &login, expires_at)
            .await?,
        LoginReserveOutcome::Reserved
    );
    let stored = admin
        .query_one(
            "SELECT key_id, ciphertext FROM \
             registry_notary_private.preauthorization_login_state \
             WHERE credential_configuration_id = 'adapter-config'",
            &[],
        )
        .await?;
    let original_key_id: Vec<u8> = stored.get("key_id");
    let stored_ciphertext: Vec<u8> = stored.get("ciphertext");
    for secret in [login.pkce_verifier.as_bytes(), login.nonce.as_bytes()] {
        assert!(
            !stored_ciphertext
                .windows(secret.len())
                .any(|window| window == secret),
            "sensitive login plaintext must not be stored"
        );
    }

    unsafe { std::env::set_var(SENSITIVE_KEY_ENV, &wrong_key) };
    let wrong_key_error = PostgresSensitiveState::activate(
        Arc::clone(&runtime),
        &SensitiveStateKeyConfig::new(SENSITIVE_KEY_ENV)?,
    )
    .await
    .expect_err("a restored wrong key must fail activation");
    assert_eq!(wrong_key_error, SensitiveStateError::InvalidStoredRecord);
    let rendered_error = wrong_key_error.to_string();
    assert!(!rendered_error.contains("adapter-pkce-secret"));
    assert!(!rendered_error.contains("adapter-login-nonce"));
    assert!(!rendered_error.contains(&primary_key));
    assert!(!rendered_error.contains(&wrong_key));
    let state_config = StateConfig {
        storage: STATE_STORAGE_POSTGRESQL.to_string(),
        postgresql: StatePostgresqlConfig {
            url_env: SENSITIVE_DATABASE_URL_ENV.to_string(),
            root_certificate_path: Some(PathBuf::from(std::env::var(DATABASE_CA_ENV)?)),
            connect_timeout_ms: 2_000,
            operation_timeout_ms: 2_000,
            max_connections: 1,
            sensitive_state_key_env: SENSITIVE_KEY_ENV.to_string(),
        },
    };
    assert_eq!(
        attest_postgres_state_plane_runtime(&state_config, true).await,
        Err(NotaryPostgresStatePlaneReadiness::ConfigurationInvalid),
        "the operator attestation boundary must reject the wrong restored key"
    );
    unsafe { std::env::set_var(SENSITIVE_KEY_ENV, &primary_key) };
    assert!(attest_postgres_state_plane_runtime(&state_config, true)
        .await
        .is_ok());
    let readiness_handle = Arc::new(NotaryStatePlaneHandle::from_config(&state_config, true)?);
    readiness_handle.activate().await?;
    assert_eq!(
        readiness_handle.readiness().await,
        NotaryPostgresStatePlaneReadiness::Ready
    );

    admin
        .execute(
            "UPDATE registry_notary_private.preauthorization_login_state \
             SET key_id = decode(repeat('ff', 32), 'hex') \
             WHERE credential_configuration_id = 'adapter-config'",
            &[],
        )
        .await?;
    assert_eq!(
        sensitive.attest_key_generation().await,
        Err(SensitiveStateError::InvalidStoredRecord),
        "readiness key attestation must fail after live-row key tampering"
    );
    assert_eq!(
        readiness_handle.readiness().await,
        NotaryPostgresStatePlaneReadiness::ConfigurationInvalid,
        "every serving readiness probe must re-attest the sensitive key"
    );
    admin
        .execute(
            "UPDATE registry_notary_private.preauthorization_login_state \
             SET key_id = $1 WHERE credential_configuration_id = 'adapter-config'",
            &[&original_key_id],
        )
        .await?;
    sensitive.attest_key_generation().await?;
    assert_eq!(
        readiness_handle.readiness().await,
        NotaryPostgresStatePlaneReadiness::Ready
    );
    let consumed = sensitive
        .consume_login("adapter-opaque-state")
        .await?
        .expect("the encrypted login must survive a fresh PostgreSQL session");
    assert_eq!(consumed.pkce_verifier, login.pkce_verifier);
    assert_eq!(consumed.nonce, login.nonce);
    assert_eq!(
        consumed.credential_configuration_id,
        login.credential_configuration_id
    );

    assert_eq!(
        sensitive
            .reserve_login("adapter-tampered-state", &login, expires_at)
            .await?,
        LoginReserveOutcome::Reserved
    );
    admin
        .execute(
            "UPDATE registry_notary_private.preauthorization_login_state \
             SET ciphertext = set_byte(ciphertext, 0, get_byte(ciphertext, 0) # 1) \
             WHERE credential_configuration_id = 'adapter-config'",
            &[],
        )
        .await?;
    assert!(
        matches!(
            sensitive.consume_login("adapter-tampered-state").await,
            Err(SensitiveStateError::InvalidStoredRecord)
        ),
        "authenticated login ciphertext tampering must fail closed"
    );

    assert!(
        sensitive
            .reserve_transaction_code("adapter-jti", "123456", 6, expires_at)
            .await?
    );
    assert!(sensitive
        .verify_transaction_code("adapter-jti", "000000")
        .await?
        .is_none());
    let proof = sensitive
        .verify_transaction_code("adapter-jti", "123456")
        .await?
        .expect("the keyed transaction-code verifier must round trip");
    let scope = registry_platform_replay::ReplayScope::new([("flow", "adapter")])?;
    assert!(
        sensitive
            .redeem(&scope, "adapter-jti", expires_at, Some(proof))
            .await?
    );

    let preauthorization_state = Arc::new(PreauthorizationState::from_state_plane(Arc::clone(
        &readiness_handle,
    ))?);
    let mismatch_jti = "adapter-policy-mismatch-jti";
    assert!(
        preauthorization_state
            .reserve_transaction_code(mismatch_jti, "654321", 6, expires_at)
            .await?
    );
    let mismatch_scope =
        registry_platform_replay::ReplayScope::new([("flow", "adapter-policy-mismatch")])?;
    assert!(
        !preauthorization_state
            .redeem(&mismatch_scope, mismatch_jti, expires_at, false, None)
            .await?,
        "a signed no-PIN requirement must reject a contradictory live verifier"
    );
    let proof = preauthorization_state
        .verify_transaction_code(mismatch_jti, "654321")
        .await?
        .expect("the rejected policy mismatch must preserve the verifier");
    assert!(
        preauthorization_state
            .redeem(&mismatch_scope, mismatch_jti, expires_at, true, Some(proof),)
            .await?,
        "the rejected policy mismatch must not consume the replay claim"
    );
    assert!(preauthorization_state
        .verify_transaction_code(mismatch_jti, "654321")
        .await?
        .is_none());
    assert!(
        !preauthorization_state
            .redeem(&mismatch_scope, mismatch_jti, expires_at, false, None)
            .await?
    );

    let transaction_id = "adapter-issuance-transaction";
    let transaction = IssuanceTransaction {
        transaction_id: transaction_id.to_string(),
        evaluation_id: "adapter-evaluation".to_string(),
        evaluation_client_id: "hmac-sha256:adapter-client".to_string(),
        credential_configuration_id: "adapter-config".to_string(),
        commitment: format!("sha256:{}", "c".repeat(64)),
        authority: IssuanceAuthority::SubjectAccess,
    };
    preauthorization_state
        .reserve_issuance_transaction(transaction_id, transaction.clone(), expires_at)
        .await?;
    assert_eq!(
        preauthorization_state
            .transaction(transaction_id)
            .await?
            .expect("encrypted transaction must round trip")
            .transaction
            .evaluation_id,
        transaction.evaluation_id.as_str()
    );
    assert!(
        !preauthorization_state
            .bind_transaction_nonce(
                transaction_id,
                &format!("sha256:{}", "d".repeat(64)),
                "adapter-token-nonce".to_string(),
            )
            .await?,
        "a mismatched commitment must not bind the token nonce"
    );
    assert!(
        preauthorization_state
            .bind_transaction_nonce(
                transaction_id,
                &transaction.commitment,
                "adapter-token-nonce".to_string(),
            )
            .await?
    );
    let acquired = preauthorization_state
        .begin_credential_materialization(
            transaction_id,
            &transaction.commitment,
            &transaction.credential_configuration_id,
            "adapter-token-nonce",
            "adapter-holder-thumbprint",
            "adapter-request-hash",
        )
        .await?;
    assert!(matches!(acquired, CredentialMaterialization::Acquired(_)));
    assert!(matches!(
        preauthorization_state
            .begin_credential_materialization(
                transaction_id,
                &transaction.commitment,
                &transaction.credential_configuration_id,
                "adapter-token-nonce",
                "adapter-holder-thumbprint",
                "adapter-request-hash",
            )
            .await?,
        CredentialMaterialization::Busy
    ));
    assert!(matches!(
        preauthorization_state
            .begin_credential_materialization(
                transaction_id,
                &transaction.commitment,
                &transaction.credential_configuration_id,
                "adapter-token-nonce",
                "different-holder",
                "adapter-request-hash",
            )
            .await?,
        CredentialMaterialization::Denied
    ));
    let cached_response = serde_json::json!({
        "format": "dc+sd-jwt",
        "credential": "adapter-signed-credential",
    });
    assert!(
        preauthorization_state
            .complete_credential_materialization(
                transaction_id,
                "adapter-holder-thumbprint",
                "adapter-request-hash",
                cached_response.clone(),
            )
            .await?
    );
    match preauthorization_state
        .begin_credential_materialization(
            transaction_id,
            &transaction.commitment,
            &transaction.credential_configuration_id,
            "adapter-token-nonce",
            "adapter-holder-thumbprint",
            "adapter-request-hash",
        )
        .await?
    {
        CredentialMaterialization::Cached(response) => {
            assert_eq!(response, cached_response);
        }
        _ => panic!("an exact PostgreSQL retry must return the cached response"),
    }
    let stored_transaction = admin
        .query_one(
            "SELECT record_ciphertext, response_ciphertext FROM \
             registry_notary_private.oid4vci_issuance_transaction",
            &[],
        )
        .await?;
    let record_ciphertext: Vec<u8> = stored_transaction.get("record_ciphertext");
    let response_ciphertext: Vec<u8> = stored_transaction.get("response_ciphertext");
    for secret in [
        transaction.evaluation_id.as_bytes(),
        transaction.evaluation_client_id.as_bytes(),
        b"adapter-signed-credential".as_slice(),
    ] {
        assert!(
            !record_ciphertext
                .windows(secret.len())
                .any(|window| window == secret)
                && !response_ciphertext
                    .windows(secret.len())
                    .any(|window| window == secret),
            "issuance transaction plaintext must not be stored"
        );
    }

    let offer_now = time::OffsetDateTime::now_utc();
    let offer_transaction = IssuanceTransaction {
        transaction_id: "adapter-registry-offer-transaction".to_string(),
        evaluation_id: "adapter-registry-offer-evaluation".to_string(),
        evaluation_client_id: "adapter-registry-client".to_string(),
        credential_configuration_id: "adapter-config".to_string(),
        commitment: format!("sha256:{}", "e".repeat(64)),
        authority: IssuanceAuthority::RegistryClient {
            initiating_client_id: "adapter-registry-client".to_string(),
            initiating_client_id_hash: format!("hmac-sha256:{}", "f".repeat(64)),
            auth_profile_id: registry_notary_core::EvidenceAuthProfileId::ExternalOidc,
            authorized_scopes: vec!["registry:evidence".to_string()],
            target_ref: registry_notary_core::TargetRefView {
                entity_type: "Person".to_string(),
                handle: "adapter-target-handle".to_string(),
                identifier_schemes: Vec::new(),
                profile: None,
            },
            service_id: "adapter.notary".to_string(),
            purpose: "civil-registration".to_string(),
        },
    };
    let offer_response = RegistryClientOfferResponse {
        credential_offer_uri: "openid-credential-offer://adapter-secret-offer".to_string(),
        tx_code: Some("246810".to_string()),
        expires_at: "2030-01-01T00:00:00Z".to_string(),
    };
    let offer_reservation = |idempotency: char, request: char, transaction: IssuanceTransaction| {
        RegistryClientOfferReservation {
            transaction_id: transaction.transaction_id.clone(),
            evaluation_id: transaction.evaluation_id.clone(),
            evaluation_expires_at: offer_now + time::Duration::minutes(20),
            idempotency_key_hash: format!("hmac-sha256:{}", idempotency.to_string().repeat(64)),
            canonical_request_hash: format!("sha256:{}", request.to_string().repeat(64)),
            transaction,
            transaction_code: Some(RegistryClientTransactionCode {
                pin: "246810".to_string(),
                pin_length: 6,
            }),
            code_expires_at: offer_now + time::Duration::minutes(5),
            transaction_expires_at: offer_now + time::Duration::minutes(15),
            response: offer_response.clone(),
            retention_expires_at: offer_now + time::Duration::minutes(10),
            quota_principal_hash: vec![0x71; 32],
            quota_limit: None,
            quota_cost: 1,
        }
    };
    let before_preflight_rows: i64 = admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_notary_private.registry_client_offer) + \
                    (SELECT count(*) FROM registry_notary_private.issuance_evaluation_consumption)",
            &[],
        )
        .await?
        .get(0);
    assert!(matches!(
        preauthorization_state
            .registry_client_offer_preflight(
                "adapter-registry-offer-evaluation",
                "adapter-registry-client",
                &format!("hmac-sha256:{}", "1".repeat(64)),
                &format!("sha256:{}", "a".repeat(64)),
            )
            .await?,
        RegistryClientOfferPreflightOutcome::Available
    ));
    let after_preflight_rows: i64 = admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_notary_private.registry_client_offer) + \
                    (SELECT count(*) FROM registry_notary_private.issuance_evaluation_consumption)",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(
        after_preflight_rows, before_preflight_rows,
        "PostgreSQL preflight must not mutate offer or evaluation state",
    );
    assert_eq!(
        preauthorization_state
            .reserve_registry_client_offer(offer_reservation('1', 'a', offer_transaction.clone(),))
            .await?,
        RegistryClientOfferReservationOutcome::Created(offer_response.clone())
    );
    assert_eq!(
        preauthorization_state
            .registry_client_offer_preflight(
                "adapter-registry-offer-evaluation",
                "adapter-registry-client",
                &format!("hmac-sha256:{}", "1".repeat(64)),
                &format!("sha256:{}", "a".repeat(64)),
            )
            .await?,
        RegistryClientOfferPreflightOutcome::Replayed(offer_response.clone())
    );
    assert!(matches!(
        preauthorization_state
            .registry_client_offer_preflight(
                "adapter-registry-offer-evaluation",
                "adapter-registry-client",
                &format!("hmac-sha256:{}", "1".repeat(64)),
                &format!("sha256:{}", "b".repeat(64)),
            )
            .await?,
        RegistryClientOfferPreflightOutcome::IdempotencyConflict
    ));
    assert!(matches!(
        preauthorization_state
            .registry_client_offer_preflight(
                "adapter-registry-offer-evaluation",
                "adapter-registry-client",
                &format!("hmac-sha256:{}", "2".repeat(64)),
                &format!("sha256:{}", "a".repeat(64)),
            )
            .await?,
        RegistryClientOfferPreflightOutcome::EvaluationConsumed
    ));
    assert_eq!(
        preauthorization_state
            .reserve_registry_client_offer(offer_reservation('1', 'a', offer_transaction.clone(),))
            .await?,
        RegistryClientOfferReservationOutcome::Replayed(offer_response.clone())
    );
    assert!(matches!(
        preauthorization_state
            .reserve_registry_client_offer(offer_reservation('1', 'b', offer_transaction.clone(),))
            .await,
        Err(PreauthorizationStateError::IdempotencyConflict)
    ));
    let mut other_transaction = offer_transaction.clone();
    other_transaction.transaction_id = "adapter-other-offer-transaction".to_string();
    assert!(matches!(
        preauthorization_state
            .reserve_registry_client_offer(offer_reservation('2', 'a', other_transaction,))
            .await,
        Err(PreauthorizationStateError::EvaluationConsumed)
    ));
    assert!(matches!(
        preauthorization_state
            .reserve_evaluation_issuance(
                "adapter-registry-offer-evaluation",
                "adapter-registry-client",
                offer_now + time::Duration::minutes(20),
            )
            .await,
        Err(PreauthorizationStateError::EvaluationConsumed)
    ));
    preauthorization_state
        .reserve_evaluation_issuance(
            "adapter-direct-first-evaluation",
            "adapter-registry-client",
            offer_now + time::Duration::minutes(20),
        )
        .await?;
    let mut direct_first_offer = offer_transaction.clone();
    direct_first_offer.transaction_id = "adapter-direct-first-offer".to_string();
    direct_first_offer.evaluation_id = "adapter-direct-first-evaluation".to_string();
    assert!(matches!(
        preauthorization_state
            .reserve_registry_client_offer(offer_reservation('3', 'a', direct_first_offer,))
            .await,
        Err(PreauthorizationStateError::EvaluationConsumed)
    ));

    let race_barrier = Arc::new(tokio::sync::Barrier::new(3));
    let direct_state = Arc::clone(&preauthorization_state);
    let direct_barrier = Arc::clone(&race_barrier);
    let direct_race = tokio::spawn(async move {
        direct_barrier.wait().await;
        direct_state
            .reserve_evaluation_issuance(
                "adapter-raced-evaluation",
                "adapter-registry-client",
                offer_now + time::Duration::minutes(20),
            )
            .await
            .map(|()| "direct")
    });
    let mut raced_transaction = offer_transaction.clone();
    raced_transaction.transaction_id = "adapter-raced-offer".to_string();
    raced_transaction.evaluation_id = "adapter-raced-evaluation".to_string();
    let raced_offer = offer_reservation('6', 'a', raced_transaction);
    let offer_state = Arc::clone(&preauthorization_state);
    let offer_barrier = Arc::clone(&race_barrier);
    let offer_race = tokio::spawn(async move {
        offer_barrier.wait().await;
        offer_state
            .reserve_registry_client_offer(raced_offer)
            .await
            .map(|_| "offer")
    });
    race_barrier.wait().await;
    let race_outcomes = [direct_race.await?, offer_race.await?];
    assert_eq!(
        race_outcomes
            .iter()
            .filter(|outcome| outcome.is_ok())
            .count(),
        1
    );
    assert_eq!(
        race_outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                Err(PreauthorizationStateError::EvaluationConsumed)
            ))
            .count(),
        1
    );

    let mut quota_transaction = offer_transaction.clone();
    quota_transaction.transaction_id = "adapter-quota-offer-one".to_string();
    quota_transaction.evaluation_id = "adapter-quota-evaluation-one".to_string();
    let mut quota_offer = offer_reservation('4', 'a', quota_transaction.clone());
    quota_offer.quota_principal_hash = vec![0xd1; 32];
    quota_offer.quota_limit = Some(1);
    assert!(matches!(
        preauthorization_state
            .reserve_registry_client_offer(quota_offer)
            .await?,
        RegistryClientOfferReservationOutcome::Created(_)
    ));
    let mut quota_replay = offer_reservation('4', 'a', quota_transaction);
    quota_replay.quota_principal_hash = vec![0xd1; 32];
    quota_replay.quota_limit = Some(1);
    assert!(matches!(
        preauthorization_state
            .reserve_registry_client_offer(quota_replay)
            .await?,
        RegistryClientOfferReservationOutcome::Replayed(_)
    ));
    let mut quota_denied_transaction = offer_transaction.clone();
    quota_denied_transaction.transaction_id = "adapter-quota-offer-two".to_string();
    quota_denied_transaction.evaluation_id = "adapter-quota-evaluation-two".to_string();
    let mut quota_denied = offer_reservation('5', 'a', quota_denied_transaction);
    quota_denied.quota_principal_hash = vec![0xd1; 32];
    quota_denied.quota_limit = Some(1);
    assert!(matches!(
        preauthorization_state
            .reserve_registry_client_offer(quota_denied)
            .await,
        Err(PreauthorizationStateError::MachineQuotaExceeded {
            retry_after_seconds: 1..=60
        })
    ));

    let quota_limiter = MachineQuotaLimiter::with_state_plane(
        registry_notary_core::MachineQuotaConfig {
            enabled: false,
            subjects_per_minute: 1,
        },
        Arc::clone(&readiness_handle),
        registry_platform_audit::AuditKeyHasher::unkeyed_dev_only(),
    );
    let fenced_request_hash = format!("sha256:{}", "d".repeat(64));
    let fenced_operation_id = format!("hmac-sha256:{}", "8".repeat(64));
    let fenced_expires_at = offer_now + time::Duration::minutes(20);
    let stale_fence = match quota_limiter
        .check_and_consume_once(
            "adapter-registry-client",
            1,
            &fenced_operation_id,
            &fenced_request_hash,
            "adapter-fenced-owner-a",
            fenced_expires_at,
        )
        .await
        .expect("initial fenced operation succeeds")
    {
        MachineQuotaOperationOutcome::Acquired(fence) => fence,
        outcome => panic!("expected initial fenced owner, got {outcome:?}"),
    };
    quota_limiter
        .release_operation(
            "adapter-registry-client",
            &fenced_operation_id,
            "adapter-fenced-owner-a",
        )
        .await
        .expect("fenced owner release succeeds");
    let current_fence = match quota_limiter
        .check_and_consume_once(
            "adapter-registry-client",
            1,
            &fenced_operation_id,
            &fenced_request_hash,
            "adapter-fenced-owner-b",
            fenced_expires_at,
        )
        .await
        .expect("fenced takeover succeeds")
    {
        MachineQuotaOperationOutcome::Acquired(fence) => fence,
        outcome => panic!("expected takeover owner, got {outcome:?}"),
    };
    let mut fenced_transaction = offer_transaction.clone();
    fenced_transaction.transaction_id = "adapter-fenced-offer".to_string();
    fenced_transaction.evaluation_id = "adapter-fenced-evaluation".to_string();
    let mut stale_reservation = offer_reservation('8', 'd', fenced_transaction.clone());
    stale_reservation.quota_principal_hash = stale_fence.principal_hash().to_vec();
    assert!(matches!(
        preauthorization_state
            .reserve_registry_client_offer_fenced(stale_reservation, &stale_fence)
            .await,
        Err(PreauthorizationStateError::OperationLeaseLost)
    ));
    let mut current_reservation = offer_reservation('8', 'd', fenced_transaction);
    current_reservation.quota_principal_hash = current_fence.principal_hash().to_vec();
    assert!(matches!(
        preauthorization_state
            .reserve_registry_client_offer_fenced(current_reservation, &current_fence)
            .await?,
        RegistryClientOfferReservationOutcome::Created(_)
    ));

    preauthorization_state
        .reserve_evaluation_issuance(
            "adapter-quota-evaluation-two",
            "adapter-registry-client",
            offer_now + time::Duration::minutes(20),
        )
        .await?;
    assert!(preauthorization_state
        .verify_transaction_code("adapter-registry-offer-transaction", "246810")
        .await?
        .is_some());
    let stored_offers = admin
        .query(
            "SELECT offer.response_ciphertext, transaction.record_ciphertext \
               FROM registry_notary_private.registry_client_offer AS offer \
               JOIN registry_notary_private.oid4vci_issuance_transaction AS transaction \
                 ON transaction.transaction_hash = offer.transaction_hash",
            &[],
        )
        .await?;
    assert!(
        !stored_offers.is_empty(),
        "registry-client offer ciphertext must be persisted"
    );
    for stored_offer in stored_offers {
        let offer_ciphertext: Vec<u8> = stored_offer.get(0);
        let transaction_ciphertext: Vec<u8> = stored_offer.get(1);
        for secret in [
            b"openid-credential-offer://adapter-secret-offer".as_slice(),
            b"246810".as_slice(),
            b"adapter-registry-client".as_slice(),
            b"adapter-target-handle".as_slice(),
        ] {
            assert!(
                !offer_ciphertext
                    .windows(secret.len())
                    .any(|window| window == secret)
                    && !transaction_ciphertext
                        .windows(secret.len())
                        .any(|window| window == secret),
                "registry-client offer plaintext must not be stored"
            );
        }
    }

    admin
        .batch_execute(
            "DELETE FROM registry_notary_private.preauthorization_login_state; \
             DELETE FROM registry_notary_private.preauthorization_tx_code; \
             DELETE FROM registry_notary_private.oid4vci_issuance_transaction; \
             DELETE FROM registry_notary_private.issuance_evaluation_consumption; \
             DELETE FROM registry_notary_private.registry_client_offer;",
        )
        .await?;

    let rotation_scope =
        registry_platform_replay::ReplayScope::new([("flow", "adapter-sensitive-key-rotation")])?;
    let rotation_jti = "adapter-sensitive-key-rotation-jti";
    assert!(
        sensitive
            .redeem(&rotation_scope, rotation_jti, expires_at, None)
            .await?,
        "the first no-PIN redemption must claim its replay identity"
    );
    // No live encrypted or PIN-verifier row remains, so rotating the
    // sensitive-state key is allowed. The replay decision must still be
    // found through its stable Notary replay hashes.
    unsafe { std::env::set_var(SENSITIVE_KEY_ENV, &wrong_key) };
    let rotated_sensitive =
        PostgresSensitiveState::activate(Arc::clone(&runtime), &key_config).await?;
    assert!(
        !rotated_sensitive
            .redeem(&rotation_scope, rotation_jti, expires_at, None)
            .await?,
        "sensitive-key rotation must not reopen a redeemed no-PIN code"
    );
    unsafe { std::env::set_var(SENSITIVE_KEY_ENV, &primary_key) };
    runtime.shutdown();
    unsafe {
        std::env::remove_var(SENSITIVE_DATABASE_URL_ENV);
        std::env::remove_var(SENSITIVE_KEY_ENV);
    }
    Ok(())
}

async fn assert_retention_contract(
    runtime: &Client,
    admin: &Client,
) -> Result<(), Box<dyn std::error::Error>> {
    admin
        .batch_execute(
            "TRUNCATE registry_notary_private.replay_identifier,
                      registry_notary_private.consumable_nonce,
                      registry_notary_private.evaluation,
                      registry_notary_private.batch_idempotency,
                      registry_notary_private.credential_status,
                      registry_notary_private.machine_quota,
                      registry_notary_private.machine_quota_operation,
                      registry_notary_private.subject_access_quota,
                      registry_notary_private.preauthorization_login_state,
                      registry_notary_private.preauthorization_tx_code,
                      registry_notary_private.oid4vci_issuance_transaction,
                      registry_notary_private.issuance_evaluation_consumption,
                      registry_notary_private.registry_client_offer;
             INSERT INTO registry_notary_private.replay_identifier
                (scope_hash, identifier_hash, created_at, expires_at)
             SELECT decode(repeat('90', 32), 'hex'), decode(repeat(marker, 32), 'hex'),
                    clock_timestamp() - interval '2 seconds',
                    clock_timestamp() + lifetime
               FROM (VALUES ('91', interval '-1 second'),
                            ('92', interval '5 minutes')) AS rows(marker, lifetime);
             INSERT INTO registry_notary_private.consumable_nonce
                (scope_hash, nonce_hash, generation, state, reservation_expires_at,
                 tombstone_expires_at, created_at, updated_at)
             SELECT decode(repeat('93', 32), 'hex'), decode(repeat(marker, 32), 'hex'),
                    1, 'reserved', clock_timestamp() + lifetime, NULL,
                    clock_timestamp() - interval '2 seconds', clock_timestamp()
               FROM (VALUES ('94', interval '-1 second'),
                            ('95', interval '5 minutes')) AS rows(marker, lifetime);
             INSERT INTO registry_notary_private.evaluation
                (evaluation_id, client_id_hash, request_hash, purpose, record_version,
                 record_json, created_at, expires_at)
             SELECT 'retention-evaluation-' || label, decode(repeat(hex_marker, 32), 'hex'),
                    decode(repeat('96', 32), 'hex'), 'retention', 2, '{}'::jsonb,
                    clock_timestamp() - interval '2 seconds', clock_timestamp() + lifetime
               FROM (VALUES ('expired', '97', interval '-1 second'),
                            ('live', '98', interval '5 minutes'))
                    AS rows(label, hex_marker, lifetime);
             INSERT INTO registry_notary_private.batch_idempotency
                (key_hash, request_hash, principal_hash, state, owner_token,
                 lease_expires_at, quota_charged, created_at, updated_at,
                 retention_expires_at)
             SELECT decode(repeat(marker, 32), 'hex'), decode(repeat('99', 32), 'hex'),
                    decode(repeat('9a', 32), 'hex'), 'failed', NULL, NULL, FALSE,
                    clock_timestamp() - interval '2 seconds', clock_timestamp(),
                    clock_timestamp() + lifetime
               FROM (VALUES ('9b', interval '-1 second'),
                            ('9c', interval '5 minutes')) AS rows(marker, lifetime);
             INSERT INTO registry_notary_private.credential_status
                (credential_id, issuer, profile, status, issued_at,
                 credential_expires_at, updated_at, purge_after)
             SELECT 'retention-credential-' || marker, 'issuer', 'profile', 'valid',
                    clock_timestamp() - interval '3 hours',
                    clock_timestamp() - interval '2 hours',
                    clock_timestamp() - interval '2 hours', clock_timestamp() + lifetime
               FROM (VALUES ('expired', interval '-1 second'),
                            ('live', interval '5 minutes')) AS rows(marker, lifetime);
             INSERT INTO registry_notary_private.machine_quota
                (principal_hash, window_started_at, window_expires_at, used)
             SELECT decode(repeat(marker, 32), 'hex'),
                    clock_timestamp() - interval '2 minutes', clock_timestamp() + lifetime, 1
               FROM (VALUES ('9d', interval '-1 second'),
                            ('9e', interval '5 minutes')) AS rows(marker, lifetime);
             INSERT INTO registry_notary_private.machine_quota_operation
                (principal_hash, operation_hash, request_hash, lease_owner_hash,
                 lease_expires_at, created_at, expires_at)
             SELECT decode(repeat(principal_marker, 32), 'hex'),
                    decode(repeat(operation_marker, 32), 'hex'),
                    decode(repeat(request_marker, 32), 'hex'),
                    decode(repeat(owner_marker, 32), 'hex'),
                    clock_timestamp() + lifetime,
                    clock_timestamp() - interval '2 seconds',
                    clock_timestamp() + lifetime
               FROM (VALUES
                    ('d0', 'd1', 'd2', 'd3', interval '-1 second'),
                    ('d4', 'd5', 'd6', 'd7', interval '5 minutes'))
                    AS rows(principal_marker, operation_marker, request_marker,
                            owner_marker, lifetime);
             INSERT INTO registry_notary_private.subject_access_quota
                (bucket_kind, key_hash, window_started_at, window_expires_at, used)
             SELECT 'per_principal', decode(repeat(marker, 32), 'hex'),
                    clock_timestamp() - interval '2 minutes', clock_timestamp() + lifetime, 1
               FROM (VALUES ('9f', interval '-1 second'),
                            ('a0', interval '5 minutes')) AS rows(marker, lifetime);
             INSERT INTO registry_notary_private.preauthorization_login_state
                (state_hash, credential_configuration_id, key_id, aead_nonce,
                 ciphertext, created_at, expires_at)
             SELECT decode(repeat(marker, 32), 'hex'), 'retention',
                    decode(repeat('a1', 32), 'hex'), decode(repeat('a2', 12), 'hex'),
                    decode(repeat('a3', 17), 'hex'), clock_timestamp() - interval '2 seconds',
                    clock_timestamp() + lifetime
               FROM (VALUES ('a4', interval '-1 second'),
                            ('a5', interval '5 minutes')) AS rows(marker, lifetime);
             INSERT INTO registry_notary_private.preauthorization_tx_code
                (jti_hash, key_id, pin_verifier, pin_length, created_at, expires_at)
             SELECT decode(repeat(marker, 32), 'hex'), decode(repeat('a6', 32), 'hex'),
                    decode(repeat('a7', 32), 'hex'), 6,
                    clock_timestamp() - interval '2 seconds', clock_timestamp() + lifetime
               FROM (VALUES ('a8', interval '-1 second'),
                            ('a9', interval '5 minutes')) AS rows(marker, lifetime);
             INSERT INTO registry_notary_private.oid4vci_issuance_transaction
                (transaction_hash, key_id, credential_configuration_id, commitment,
                 record_aead_nonce, record_ciphertext, state, created_at, updated_at,
                 expires_at)
             SELECT decode(repeat(marker, 32), 'hex'), decode(repeat('b2', 32), 'hex'),
                    'retention', 'sha256:' || repeat('c', 64),
                    decode(repeat('b3', 12), 'hex'),
                    decode(repeat('b4', 17), 'hex'), 'ready',
                    clock_timestamp() - interval '2 seconds', clock_timestamp(),
                    clock_timestamp() + lifetime
               FROM (VALUES ('b0', interval '-1 second'),
                            ('b1', interval '5 minutes')) AS rows(marker, lifetime);
             INSERT INTO registry_notary_private.issuance_evaluation_consumption
                (evaluation_hash, key_id, created_at, expires_at)
             SELECT decode(repeat(marker, 32), 'hex'),
                    decode(repeat('c8', 32), 'hex'),
                    clock_timestamp() - interval '2 seconds',
                    clock_timestamp() + lifetime
               FROM (VALUES ('cc', interval '-1 second'),
                            ('cd', interval '5 minutes')) AS rows(marker, lifetime);
             INSERT INTO registry_notary_private.registry_client_offer
                (idempotency_key_hash, request_hash, evaluation_hash,
                 transaction_hash, key_id, response_aead_nonce,
                 response_ciphertext, retention_expires_at,
                 evaluation_expires_at, purge_after, created_at)
             SELECT decode(repeat(marker, 32), 'hex'),
                    decode(repeat(request_marker, 32), 'hex'),
                    decode(repeat(evaluation_marker, 32), 'hex'),
                    decode(repeat(transaction_marker, 32), 'hex'),
                    decode(repeat('c9', 32), 'hex'),
                    decode(repeat('ca', 12), 'hex'),
                    decode(repeat('cb', 17), 'hex'),
                    pg_catalog.statement_timestamp() + lifetime,
                    pg_catalog.statement_timestamp() + lifetime,
                    pg_catalog.statement_timestamp() + lifetime,
                    clock_timestamp() - interval '2 seconds'
               FROM (VALUES
                    ('c0', 'c1', 'c2', 'c3', interval '-1 second'),
                    ('c4', 'c5', 'c6', 'c7', interval '5 minutes'))
                    AS rows(marker, request_marker, evaluation_marker,
                            transaction_marker, lifetime);",
        )
        .await?;
    let prune = runtime
        .query_one(
            "SELECT deleted_count, batch_saturated \
               FROM registry_notary_api.retention_prune_v1(1000)",
            &[],
        )
        .await?;
    let pruned: i64 = prune.get("deleted_count");
    assert_eq!(
        pruned, 13,
        "each typed state table must prune its expired row"
    );
    assert!(
        !prune.get::<_, bool>("batch_saturated"),
        "a short per-table pass must report that catch-up is complete"
    );
    let remaining: i64 = admin
        .query_one(
            "SELECT
                (SELECT count(*) FROM registry_notary_private.replay_identifier) +
                (SELECT count(*) FROM registry_notary_private.consumable_nonce) +
                (SELECT count(*) FROM registry_notary_private.evaluation) +
                (SELECT count(*) FROM registry_notary_private.batch_idempotency) +
                (SELECT count(*) FROM registry_notary_private.credential_status) +
                (SELECT count(*) FROM registry_notary_private.machine_quota) +
                (SELECT count(*) FROM registry_notary_private.machine_quota_operation) +
                (SELECT count(*) FROM registry_notary_private.subject_access_quota) +
                (SELECT count(*) FROM registry_notary_private.preauthorization_login_state) +
                (SELECT count(*) FROM registry_notary_private.preauthorization_tx_code) +
                (SELECT count(*) FROM registry_notary_private.oid4vci_issuance_transaction) +
                (SELECT count(*) FROM registry_notary_private.issuance_evaluation_consumption) +
                (SELECT count(*) FROM registry_notary_private.registry_client_offer)",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(remaining, 13, "retention must preserve every live row");

    admin
        .batch_execute(
            "INSERT INTO registry_notary_private.evaluation
                (evaluation_id, client_id_hash, request_hash, purpose, record_version,
                 record_json, created_at, expires_at)
             SELECT 'retention-backlog-' || sequence,
                    decode(repeat('aa', 32), 'hex'),
                    decode(repeat('ab', 32), 'hex'),
                    'retention-backlog', 2, '{}'::jsonb,
                    clock_timestamp() - interval '2 minutes',
                    clock_timestamp() - interval '1 minute'
               FROM pg_catalog.generate_series(1, 1001) AS sequence;",
        )
        .await?;
    let saturated = runtime
        .query_one(
            "SELECT deleted_count, batch_saturated \
               FROM registry_notary_api.retention_prune_v1(1000)",
            &[],
        )
        .await?;
    assert_eq!(saturated.get::<_, i64>("deleted_count"), 1_000);
    assert!(
        saturated.get::<_, bool>("batch_saturated"),
        "a full batch from any one table must request another transaction"
    );
    let caught_up = runtime
        .query_one(
            "SELECT deleted_count, batch_saturated \
               FROM registry_notary_api.retention_prune_v1(1000)",
            &[],
        )
        .await?;
    assert_eq!(caught_up.get::<_, i64>("deleted_count"), 1);
    assert!(
        !caught_up.get::<_, bool>("batch_saturated"),
        "the short follow-up batch must terminate catch-up"
    );
    let expired_backlog: i64 = admin
        .query_one(
            "SELECT count(*) FROM registry_notary_private.evaluation \
              WHERE expires_at <= clock_timestamp()",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(
        expired_backlog, 0,
        "catch-up must drain the expired backlog"
    );
    Ok(())
}

async fn subject_access_quota_decision(
    client: &Client,
    statement: &'static str,
    bucket_kinds: &[String],
    key_hashes: &[Vec<u8>],
    limits: &[i32],
    window_seconds: &[i32],
) -> Result<(bool, Option<String>), tokio_postgres::Error> {
    let row = client
        .query_one(
            statement,
            &[&bucket_kinds, &key_hashes, &limits, &window_seconds],
        )
        .await?;
    Ok((row.try_get("allowed")?, row.try_get("denied_bucket")?))
}

async fn connect_as(
    database_url: &str,
    role: &str,
) -> Result<
    (
        Client,
        tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
    ),
    Box<dyn std::error::Error>,
> {
    let mut config: tokio_postgres::Config = database_url.parse()?;
    config.user(role);
    if config.get_ssl_mode() == tokio_postgres::config::SslMode::Disable {
        let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
        return Ok((client, tokio::spawn(connection)));
    }
    let ca_path = std::env::var(DATABASE_CA_ENV)?;
    let ca_pem = std::fs::read(ca_path)?;
    let ca = native_tls::Certificate::from_pem(&ca_pem)?;
    let mut tls = native_tls::TlsConnector::builder();
    tls.add_root_certificate(ca);
    let tls = postgres_native_tls::MakeTlsConnector::new(tls.build()?);
    let (client, connection) = config.connect(tls).await?;
    Ok((client, tokio::spawn(connection)))
}
