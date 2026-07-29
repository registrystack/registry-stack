// SPDX-License-Identifier: Apache-2.0
//! Forward-only installation and attestation for Notary PostgreSQL state v1.
//!
//! The owner connection applies this migration explicitly. Normal Notary
//! startup uses only the separately attested runtime role and never applies
//! DDL. Relay schemas, roles, migrations, and advisory locks are intentionally
//! not reused.

use std::fmt;

use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_postgres::{Client, GenericClient, Row, Transaction};

pub const STATE_PLANE_CAPABILITY_V1: &str = "registry.notary.postgresql-state/v1";
pub const STATE_PLANE_SCHEMA_VERSION_V1: i32 = 1;
// This semantic identity changes when a typed state domain or a cross-runtime
// correctness invariant changes. Exact PostgreSQL structure and executable
// bodies are attested separately by the per-major catalog fingerprints.
#[cfg(test)]
const STATE_PLANE_SCHEMA_IDENTITY_PREIMAGE_V1: &str = concat!(
    "registry.notary.postgresql-state.semantic-identity.v1\0",
    "schema-version=1\0",
    "schema=notary-owned-private-tables-fixed-typed-api-functions-v1\0",
    "roles=owner-nologin-migration-assumption-runtime-execute-only-no-private-access-v1\0",
    "database=postgresql-16-17-18-writable-safe-durability-database-clock-v1\0",
    "replay=keyed-scope-identifier-one-winner-expiry-replacement-v1\0",
    "nonce=keyed-generation-reserve-compare-consume-sixty-second-tombstone-v2\0",
    "evaluation=client-bound-stored-record-v2-atomic-publication-expiry-v1\0",
    "batch=keyed-request-owner-lease-quota-once-takeover-atomic-completion-stored-response-v2-fifteen-minute-retention-v1\0",
    "credential-status=insert-only-locked-transition-terminal-revocation-database-clock-effective-expiry-before-suspension-retention-monotonic-updated-at-v2\0",
    "machine-quota=keyed-principal-fixed-minute-whole-cost-atomic-v1\0",
    "subject-access-quota=keyed-pseudonym-six-closed-buckets-fixed-windows-canonical-lock-order-caller-denial-order-atomic-all-or-none-check-only-no-mutation-v1\0",
    "preauthorization-login=keyed-state-capacity-4096-encrypted-single-consume-expiry-live-key-attestation-v2\0",
    "preauthorization-tx-code=verified-notary-issuer-stable-scope-jti-keyed-pin-verifier-peek-redeem-one-winner-expiry-live-key-attestation-v3\0",
    "oid4vci-issuance-transaction=keyed-id-encrypted-immutable-record-sha256-uri-commitment-token-nonce-bind-holder-and-request-atomic-one-materialization-encrypted-response-terminal-failure-expiry-v2\0",
    "issuance-evaluation-consumption=keyed-owner-evaluation-single-lineage-shared-direct-and-offer-expiry-capacity-v1\0",
    "registry-client-offer=hashed-idempotency-exact-encrypted-response-shared-evaluation-consumption-atomic-client-quota-transaction-and-optional-pin-expiry-capacity-v2\0",
    "retention=bounded-expiry-prune-skip-locked-saturation-catch-up-v2\0",
);
pub const STATE_PLANE_SCHEMA_FINGERPRINT_V1: &str =
    "56e32f72f7cfb555487e0e1b94959780c24d0a4e2427496766ad03c135c65313";
// The immediately preceding v1 contract is the only supported in-place
// upgrade source. Its exact catalog is attested before any DDL runs.
const PREVIOUS_STATE_PLANE_SCHEMA_FINGERPRINT_V1: &str =
    "f08bb0bc9b927b534ce736c640d43e3c7f898bd110616f92a60857c5fd1323fd";

const MIGRATION_ADVISORY_LOCK_KEY_V1: i64 = 0x4e4f_5441_5259_0001;
const EXPECTED_PRIVATE_TABLE_COUNT_V1: i64 = 13;
const EXPECTED_API_FUNCTION_COUNT_V1: i64 = 33;

/// The `NOLOGIN` role that owns the Notary schemas and fixed functions.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerDatabaseRole(String);

impl OwnerDatabaseRole {
    pub fn parse(value: impl Into<String>) -> Result<Self, StatePlaneMigrationError> {
        parse_role_name(value.into())
            .map(Self)
            .map_err(|()| StatePlaneMigrationError::InvalidOwnerRole)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OwnerDatabaseRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnerDatabaseRole")
            .field("name", &"<redacted>")
            .finish()
    }
}

/// A pre-provisioned login role used only by the Notary runtime.
///
/// Role names are deliberately restricted to unquoted PostgreSQL identifiers.
/// This makes the small DCL fragment non-injectable without adding a general
/// SQL identifier-quoting abstraction to a security-sensitive installer.
#[derive(Clone, PartialEq, Eq)]
pub struct RuntimeDatabaseRole(String);

impl RuntimeDatabaseRole {
    pub fn parse(value: impl Into<String>) -> Result<Self, StatePlaneMigrationError> {
        parse_role_name(value.into())
            .map(Self)
            .map_err(|()| StatePlaneMigrationError::InvalidRuntimeRole)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn parse_role_name(value: String) -> Result<String, ()> {
    let mut chars = value.chars();
    let valid_first = chars
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_lowercase());
    let valid_rest = chars.all(|character| {
        character == '_' || character.is_ascii_lowercase() || character.is_ascii_digit()
    });
    if value.len() > 63 || !valid_first || !valid_rest {
        return Err(());
    }
    Ok(value)
}

impl fmt::Debug for RuntimeDatabaseRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDatabaseRole")
            .field("name", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StatePlaneMigrationError {
    #[error("Notary PostgreSQL runtime role is invalid")]
    InvalidRuntimeRole,
    #[error("Notary PostgreSQL owner role is invalid")]
    InvalidOwnerRole,
    #[error("Notary PostgreSQL migration role cannot assume the owner role")]
    OwnerRoleUnavailable,
    #[error("Notary PostgreSQL runtime role is unavailable or unsafe")]
    InvalidRuntimeRoleContract,
    #[error("Notary PostgreSQL owner and runtime roles must be distinct")]
    RoleCollision,
    #[error("Notary PostgreSQL server major is unsupported")]
    UnsupportedServerMajor,
    #[error("Notary PostgreSQL database is read-only or recovering")]
    DatabaseNotWritable,
    #[error("Notary PostgreSQL durability settings are unsafe")]
    UnsafeDurability,
    #[error("Notary PostgreSQL state schema is partially installed")]
    PartialInstallation,
    #[error("Notary PostgreSQL state capability has drifted")]
    CapabilityDrift,
    #[error("Notary PostgreSQL state operation is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostgresStatePlaneAttestation {
    pub server_major: i32,
    pub schema_version: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BoundRoleOids {
    owner: i64,
    runtime: i64,
}

#[derive(Debug, Clone)]
struct CapabilityBinding {
    roles: BoundRoleOids,
    server_major: i32,
}

pub async fn install_postgres_state_plane_v1(
    client: &mut Client,
    owner_role: &OwnerDatabaseRole,
    runtime_role: &RuntimeDatabaseRole,
) -> Result<PostgresStatePlaneAttestation, StatePlaneMigrationError> {
    let transaction = client
        .transaction()
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    transaction
        .batch_execute(
            "SET LOCAL lock_timeout = '5s';\n\
             SET LOCAL statement_timeout = '30s';\n\
             SET LOCAL idle_in_transaction_session_timeout = '30s'",
        )
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    transaction
        .query_one(
            "SELECT pg_catalog.pg_advisory_xact_lock($1)",
            &[&MIGRATION_ADVISORY_LOCK_KEY_V1],
        )
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;

    let server_major = attest_server(&transaction).await?;
    let role_oids =
        validate_and_assume_install_roles(&transaction, owner_role, runtime_role).await?;
    let schema_count = schema_count(&transaction).await?;
    match schema_count {
        0 => {
            transaction
                .batch_execute(POSTGRES_STATE_PLANE_MIGRATION_V1)
                .await
                .map_err(|_| StatePlaneMigrationError::Unavailable)?;
            bind_metadata(&transaction, role_oids).await?;
            transaction
                .batch_execute(&state_plane_acl_sql(runtime_role))
                .await
                .map_err(|_| StatePlaneMigrationError::Unavailable)?;
        }
        2 => {
            // Prove ownership and the complete catalog through public catalog
            // data before inspecting private metadata. A wrong owner or an
            // unknown catalog must fail closed as drift without gaining access
            // to restored state.
            attest_catalog_ownership(&transaction, role_oids.owner).await?;
            let observed_catalog = catalog_definition_fingerprint(&transaction).await?;
            if observed_catalog == expected_catalog_definition_fingerprint(server_major)? {
                if installed_schema_fingerprint(&transaction).await?
                    != STATE_PLANE_SCHEMA_FINGERPRINT_V1
                {
                    return Err(StatePlaneMigrationError::CapabilityDrift);
                }
                rebind_restored_metadata(&transaction, role_oids, runtime_role, server_major)
                    .await?;
            } else if observed_catalog
                == expected_previous_catalog_definition_fingerprint(server_major)?
            {
                if installed_schema_fingerprint(&transaction).await?
                    != PREVIOUS_STATE_PLANE_SCHEMA_FINGERPRINT_V1
                {
                    return Err(StatePlaneMigrationError::CapabilityDrift);
                }
                upgrade_previous_state_plane(&transaction, role_oids, runtime_role, server_major)
                    .await?;
            } else {
                return Err(StatePlaneMigrationError::CapabilityDrift);
            }
        }
        _ => return Err(StatePlaneMigrationError::PartialInstallation),
    }
    attest_owner_metadata(&transaction, role_oids).await?;
    attest_catalog_shape(&transaction, role_oids, server_major).await?;
    transaction
        .commit()
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    Ok(PostgresStatePlaneAttestation {
        server_major,
        schema_version: STATE_PLANE_SCHEMA_VERSION_V1,
    })
}

pub async fn attest_postgres_state_plane_v1(
    client: &Client,
) -> Result<PostgresStatePlaneAttestation, StatePlaneMigrationError> {
    let server_major = attest_server(client).await?;
    let binding = runtime_capability_binding(client).await?;
    if binding.server_major != server_major {
        return Err(StatePlaneMigrationError::CapabilityDrift);
    }
    attest_catalog_shape(client, binding.roles, server_major).await?;
    Ok(PostgresStatePlaneAttestation {
        server_major,
        schema_version: STATE_PLANE_SCHEMA_VERSION_V1,
    })
}

async fn runtime_capability_binding(
    client: &Client,
) -> Result<CapabilityBinding, StatePlaneMigrationError> {
    let row = client
        .query_opt("SELECT * FROM registry_notary_api.attest_v1()", &[])
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?
        .ok_or(StatePlaneMigrationError::CapabilityDrift)?;
    let capability: String = row
        .try_get("capability_id")
        .map_err(|_| StatePlaneMigrationError::CapabilityDrift)?;
    let fingerprint: String = row
        .try_get("schema_fingerprint")
        .map_err(|_| StatePlaneMigrationError::CapabilityDrift)?;
    let schema_version = row_i32(&row, "schema_version")?;
    let roles = BoundRoleOids {
        owner: row_i64(&row, "owner_role_oid")?,
        runtime: row_i64(&row, "runtime_role_oid")?,
    };
    if row_i64(&row, "caller_role_oid")? != roles.runtime {
        return Err(StatePlaneMigrationError::InvalidRuntimeRoleContract);
    }
    if capability != STATE_PLANE_CAPABILITY_V1
        || schema_version != STATE_PLANE_SCHEMA_VERSION_V1
        || fingerprint != STATE_PLANE_SCHEMA_FINGERPRINT_V1
        || !row_bool(&row, "database_writable")?
        || !row_bool(&row, "durability_safe")?
    {
        return Err(StatePlaneMigrationError::CapabilityDrift);
    }
    Ok(CapabilityBinding {
        roles,
        server_major: row_i32(&row, "server_major")?,
    })
}

async fn attest_server(client: &impl GenericClient) -> Result<i32, StatePlaneMigrationError> {
    let row = client
        .query_one(
            "SELECT current_setting('server_version_num')::integer / 10000 AS server_major,\n\
                    NOT pg_catalog.pg_is_in_recovery()\n\
                      AND NOT current_setting('transaction_read_only')::boolean AS writable,\n\
                    current_setting('fsync') = 'on'\n\
                      AND current_setting('synchronous_commit') = 'on'\n\
                      AND current_setting('full_page_writes') = 'on' AS durable",
            &[],
        )
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    let server_major = row_i32(&row, "server_major")?;
    if !(16..=18).contains(&server_major) {
        return Err(StatePlaneMigrationError::UnsupportedServerMajor);
    }
    if !row_bool(&row, "writable")? {
        return Err(StatePlaneMigrationError::DatabaseNotWritable);
    }
    if !row_bool(&row, "durable")? {
        return Err(StatePlaneMigrationError::UnsafeDurability);
    }
    Ok(server_major)
}

async fn validate_and_assume_install_roles(
    transaction: &Transaction<'_>,
    owner_role: &OwnerDatabaseRole,
    runtime_role: &RuntimeDatabaseRole,
) -> Result<BoundRoleOids, StatePlaneMigrationError> {
    let row = transaction
        .query_opt(
            "SELECT owner_role.oid::bigint AS owner_oid,\n\
                    runtime_role.oid::bigint AS runtime_oid,\n\
                    migration_role.rolcanlogin\n\
                      AND NOT migration_role.rolsuper\n\
                      AND NOT migration_role.rolcreaterole\n\
                      AND NOT migration_role.rolcreatedb\n\
                      AND NOT migration_role.rolreplication\n\
                      AND NOT migration_role.rolbypassrls AS migration_safe,\n\
                    NOT owner_role.rolcanlogin\n\
                      AND NOT owner_role.rolsuper\n\
                      AND NOT owner_role.rolcreaterole\n\
                      AND NOT owner_role.rolcreatedb\n\
                      AND NOT owner_role.rolreplication\n\
                      AND NOT owner_role.rolbypassrls AS owner_safe,\n\
                    runtime_role.rolcanlogin\n\
                      AND NOT runtime_role.rolsuper\n\
                      AND NOT runtime_role.rolcreaterole\n\
                      AND NOT runtime_role.rolcreatedb\n\
                      AND NOT runtime_role.rolreplication\n\
                      AND NOT runtime_role.rolbypassrls AS runtime_safe,\n\
                    NOT pg_catalog.pg_has_role(runtime_role.oid, owner_role.oid, 'MEMBER')\n\
                      AS runtime_not_owner_member,\n\
                    pg_catalog.pg_has_role(migration_role.oid, owner_role.oid, 'MEMBER')\n\
                      AS migration_may_assume_owner,\n\
                    migration_role.oid <> owner_role.oid AS migration_is_distinct\n\
               FROM pg_catalog.pg_roles AS migration_role\n\
               JOIN pg_catalog.pg_roles AS owner_role ON owner_role.rolname = $1\n\
               JOIN pg_catalog.pg_roles AS runtime_role ON runtime_role.rolname = $2\n\
              WHERE migration_role.rolname = session_user\n\
                AND current_user = session_user",
            &[&owner_role.as_str(), &runtime_role.as_str()],
        )
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?
        .ok_or(StatePlaneMigrationError::InvalidRuntimeRoleContract)?;
    if !row_bool(&row, "migration_safe")?
        || !row_bool(&row, "migration_may_assume_owner")?
        || !row_bool(&row, "migration_is_distinct")?
    {
        return Err(StatePlaneMigrationError::OwnerRoleUnavailable);
    }
    if !row_bool(&row, "owner_safe")? {
        return Err(StatePlaneMigrationError::InvalidOwnerRole);
    }
    if !row_bool(&row, "runtime_safe")? || !row_bool(&row, "runtime_not_owner_member")? {
        return Err(StatePlaneMigrationError::InvalidRuntimeRoleContract);
    }
    let oids = BoundRoleOids {
        owner: row_i64(&row, "owner_oid")?,
        runtime: row_i64(&row, "runtime_oid")?,
    };
    if oids.owner == oids.runtime {
        return Err(StatePlaneMigrationError::RoleCollision);
    }
    transaction
        .batch_execute(&format!("SET LOCAL ROLE {}", owner_role.as_str()))
        .await
        .map_err(|_| StatePlaneMigrationError::OwnerRoleUnavailable)?;
    let assumed = transaction
        .query_one(
            "SELECT current_role = $1 AND session_user <> current_user AS assumed",
            &[&owner_role.as_str()],
        )
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    if !row_bool(&assumed, "assumed")? {
        return Err(StatePlaneMigrationError::OwnerRoleUnavailable);
    }
    Ok(oids)
}

async fn schema_count(client: &impl GenericClient) -> Result<i64, StatePlaneMigrationError> {
    let row = client
        .query_one(
            "SELECT count(*)::bigint AS schema_count\n\
               FROM pg_catalog.pg_namespace\n\
              WHERE nspname IN ('registry_notary_private', 'registry_notary_api')",
            &[],
        )
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    row_i64(&row, "schema_count")
}

async fn installed_schema_fingerprint(
    client: &impl GenericClient,
) -> Result<String, StatePlaneMigrationError> {
    let row = client
        .query_opt(
            "SELECT capability_id, schema_version, schema_fingerprint\n\
               FROM registry_notary_private.schema_metadata\n\
              WHERE singleton\n\
              FOR UPDATE",
            &[],
        )
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?
        .ok_or(StatePlaneMigrationError::CapabilityDrift)?;
    let capability: String = row
        .try_get("capability_id")
        .map_err(|_| StatePlaneMigrationError::CapabilityDrift)?;
    if capability != STATE_PLANE_CAPABILITY_V1
        || row_i32(&row, "schema_version")? != STATE_PLANE_SCHEMA_VERSION_V1
    {
        return Err(StatePlaneMigrationError::CapabilityDrift);
    }
    row.try_get("schema_fingerprint")
        .map_err(|_| StatePlaneMigrationError::CapabilityDrift)
}

async fn bind_metadata(
    transaction: &Transaction<'_>,
    roles: BoundRoleOids,
) -> Result<(), StatePlaneMigrationError> {
    transaction
        .execute(
            "INSERT INTO registry_notary_private.schema_metadata (\n\
                 singleton, capability_id, schema_version, schema_fingerprint,\n\
                 owner_role_oid, runtime_role_oid\n\
             ) VALUES (TRUE, $1, $2, $3, $4::bigint::oid, $5::bigint::oid)",
            &[
                &STATE_PLANE_CAPABILITY_V1,
                &STATE_PLANE_SCHEMA_VERSION_V1,
                &STATE_PLANE_SCHEMA_FINGERPRINT_V1,
                &roles.owner,
                &roles.runtime,
            ],
        )
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    Ok(())
}

fn state_plane_acl_sql(runtime_role: &RuntimeDatabaseRole) -> String {
    let role = runtime_role.as_str();
    format!(
        "REVOKE ALL ON SCHEMA registry_notary_private FROM PUBLIC;\n\
         REVOKE ALL ON SCHEMA registry_notary_api FROM PUBLIC;\n\
         REVOKE ALL ON ALL TABLES IN SCHEMA registry_notary_private FROM PUBLIC;\n\
         REVOKE ALL ON ALL SEQUENCES IN SCHEMA registry_notary_private FROM PUBLIC;\n\
         REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA registry_notary_private FROM PUBLIC;\n\
         REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA registry_notary_api FROM PUBLIC;\n\
         REVOKE ALL ON SCHEMA registry_notary_private FROM {role};\n\
         REVOKE ALL ON ALL TABLES IN SCHEMA registry_notary_private FROM {role};\n\
         REVOKE ALL ON ALL SEQUENCES IN SCHEMA registry_notary_private FROM {role};\n\
         REVOKE ALL ON ALL FUNCTIONS IN SCHEMA registry_notary_private FROM {role};\n\
         REVOKE ALL ON SCHEMA registry_notary_api FROM {role};\n\
         REVOKE ALL ON ALL FUNCTIONS IN SCHEMA registry_notary_api FROM {role};\n\
         GRANT USAGE ON SCHEMA registry_notary_api TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.attest_v1() TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.readiness_v1() TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.replay_insert_v1(bytea, bytea, timestamptz) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.nonce_reserve_v1(bytea, bytea, timestamptz) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.nonce_reservation_generation_v1(bytea, bytea) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.nonce_consume_v1(bytea, bytea, bigint) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.evaluation_insert_v1(text, bytea, bytea, text, smallint, jsonb, timestamptz, timestamptz) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.evaluation_get_v1(text, bytea) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.batch_reserve_v1(bytea, bytea, bytea, bytea, integer, integer, integer) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.batch_heartbeat_v1(bytea, bytea, bytea, integer) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.batch_complete_v1(bytea, bytea, bytea, jsonb, smallint, jsonb) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.batch_fail_v1(bytea, bytea, bytea) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.credential_status_insert_v1(text, text, text, timestamptz, timestamptz, integer) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.credential_status_get_v1(text) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.credential_status_update_v1(text, text) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.machine_quota_debit_v1(bytea, integer, integer) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.subject_access_quota_debit_v1(text[], bytea[], integer[], integer[]) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.subject_access_quota_check_v1(text[], bytea[], integer[], integer[]) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.preauthorization_login_reserve_v1(bytea, text, bytea, bytea, bytea, timestamptz) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.preauthorization_login_consume_v1(bytea) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.preauthorization_tx_code_reserve_v1(bytea, bytea, bytea, smallint, timestamptz) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.preauthorization_tx_code_peek_v1(bytea) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.preauthorization_key_attest_v1(bytea) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.preauthorization_redeem_v1(bytea, bytea, timestamptz, boolean, bytea) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.evaluation_issuance_consume_v1(bytea, bytea, timestamptz) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.registry_client_offer_reserve_v1(bytea, bytea, bytea, bytea, bytea, bytea, text, text, bytea, bytea, timestamptz, bytea, smallint, timestamptz, bytea, bytea, timestamptz, timestamptz, bytea, integer, integer) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.oid4vci_transaction_reserve_v1(bytea, bytea, text, text, bytea, bytea, timestamptz) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.oid4vci_transaction_get_v1(bytea) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.oid4vci_transaction_bind_nonce_v1(bytea, text, bytea) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.oid4vci_transaction_begin_v1(bytea, text, text, bytea, bytea, bytea) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.oid4vci_transaction_complete_v1(bytea, bytea, bytea, bytea, bytea) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.oid4vci_transaction_fail_v1(bytea, bytea) TO {role};\n\
         GRANT EXECUTE ON FUNCTION registry_notary_api.retention_prune_v1(integer) TO {role};"
    )
}

async fn rebind_restored_metadata(
    transaction: &Transaction<'_>,
    roles: BoundRoleOids,
    runtime_role: &RuntimeDatabaseRole,
    server_major: i32,
) -> Result<(), StatePlaneMigrationError> {
    // The candidate owner must already own the complete exact v1 catalog.
    // Check this through pg_catalog before reading private metadata so a wrong
    // owner is rejected as drift rather than gaining enough access to inspect
    // or repair the restored schema.
    attest_catalog_ownership_and_definition(
        transaction,
        roles.owner,
        expected_catalog_definition_fingerprint(server_major)?,
    )
    .await?;
    let observed_roles = metadata_roles_for_exact_v1(transaction).await?;
    if observed_roles == roles {
        transaction
            .batch_execute(&state_plane_acl_sql(runtime_role))
            .await
            .map_err(|_| StatePlaneMigrationError::Unavailable)?;
        return Ok(());
    }

    // A logical restore may preserve the exact schema and rows while role OIDs
    // change across clusters. Rebind only after proving that every restored
    // object is already owned by the newly provisioned owner and that the live
    // catalog is the compiled v1 contract. This never changes object ownership.
    let updated = transaction
        .execute(
            "UPDATE registry_notary_private.schema_metadata\n\
                SET owner_role_oid = $1::bigint::oid,\n\
                    runtime_role_oid = $2::bigint::oid\n\
              WHERE singleton\n\
                AND capability_id = $3\n\
                AND schema_version = $4\n\
                AND schema_fingerprint = $5",
            &[
                &roles.owner,
                &roles.runtime,
                &STATE_PLANE_CAPABILITY_V1,
                &STATE_PLANE_SCHEMA_VERSION_V1,
                &STATE_PLANE_SCHEMA_FINGERPRINT_V1,
            ],
        )
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    if updated != 1 {
        return Err(StatePlaneMigrationError::CapabilityDrift);
    }
    transaction
        .batch_execute(&state_plane_acl_sql(runtime_role))
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    Ok(())
}

async fn upgrade_previous_state_plane(
    transaction: &Transaction<'_>,
    roles: BoundRoleOids,
    runtime_role: &RuntimeDatabaseRole,
    server_major: i32,
) -> Result<(), StatePlaneMigrationError> {
    // An upgrade is allowed only from the exact previously released catalog,
    // already wholly owned by the candidate owner. This keeps the idempotent
    // DDL below from accepting or concealing arbitrary catalog drift.
    attest_catalog_ownership_and_definition(
        transaction,
        roles.owner,
        expected_previous_catalog_definition_fingerprint(server_major)?,
    )
    .await?;
    transaction
        .batch_execute(POSTGRES_STATE_PLANE_MIGRATION_V1)
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    let updated = transaction
        .execute(
            "UPDATE registry_notary_private.schema_metadata\n\
                SET schema_fingerprint = $1,\n\
                    owner_role_oid = $2::bigint::oid,\n\
                    runtime_role_oid = $3::bigint::oid\n\
              WHERE singleton\n\
                AND capability_id = $4\n\
                AND schema_version = $5\n\
                AND schema_fingerprint = $6",
            &[
                &STATE_PLANE_SCHEMA_FINGERPRINT_V1,
                &roles.owner,
                &roles.runtime,
                &STATE_PLANE_CAPABILITY_V1,
                &STATE_PLANE_SCHEMA_VERSION_V1,
                &PREVIOUS_STATE_PLANE_SCHEMA_FINGERPRINT_V1,
            ],
        )
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    if updated != 1 {
        return Err(StatePlaneMigrationError::CapabilityDrift);
    }
    transaction
        .batch_execute(&state_plane_acl_sql(runtime_role))
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    Ok(())
}

async fn metadata_roles_for_exact_v1(
    client: &impl GenericClient,
) -> Result<BoundRoleOids, StatePlaneMigrationError> {
    let row = client
        .query_opt(
            "SELECT metadata.capability_id, metadata.schema_version,\n\
                    metadata.schema_fingerprint, metadata.owner_role_oid::bigint AS owner_oid,\n\
                    metadata.runtime_role_oid::bigint AS runtime_oid\n\
               FROM registry_notary_private.schema_metadata AS metadata\n\
              WHERE metadata.singleton",
            &[],
        )
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?
        .ok_or(StatePlaneMigrationError::CapabilityDrift)?;
    let capability: String = row
        .try_get("capability_id")
        .map_err(|_| StatePlaneMigrationError::CapabilityDrift)?;
    let fingerprint: String = row
        .try_get("schema_fingerprint")
        .map_err(|_| StatePlaneMigrationError::CapabilityDrift)?;
    if capability != STATE_PLANE_CAPABILITY_V1
        || row_i32(&row, "schema_version")? != STATE_PLANE_SCHEMA_VERSION_V1
        || fingerprint != STATE_PLANE_SCHEMA_FINGERPRINT_V1
    {
        return Err(StatePlaneMigrationError::CapabilityDrift);
    }
    Ok(BoundRoleOids {
        owner: row_i64(&row, "owner_oid")?,
        runtime: row_i64(&row, "runtime_oid")?,
    })
}

async fn attest_catalog_ownership_and_definition(
    client: &impl GenericClient,
    owner_oid: i64,
    expected_fingerprint: &str,
) -> Result<(), StatePlaneMigrationError> {
    attest_catalog_ownership(client, owner_oid).await?;
    let observed = catalog_definition_fingerprint(client).await?;
    if observed != expected_fingerprint {
        return Err(StatePlaneMigrationError::CapabilityDrift);
    }
    Ok(())
}

async fn attest_catalog_ownership(
    client: &impl GenericClient,
    owner_oid: i64,
) -> Result<(), StatePlaneMigrationError> {
    let ownership = client
        .query_one(
            "SELECT (SELECT count(*) = 2 AND bool_and(namespace.nspowner = $1::bigint::oid)\n\
                       FROM pg_catalog.pg_namespace AS namespace\n\
                      WHERE namespace.nspname IN ('registry_notary_private',\n\
                                                   'registry_notary_api')) AS schemas_owned,\n\
                    NOT EXISTS (\n\
                      SELECT 1 FROM pg_catalog.pg_class AS relation\n\
                      JOIN pg_catalog.pg_namespace AS namespace\n\
                        ON namespace.oid = relation.relnamespace\n\
                     WHERE namespace.nspname IN ('registry_notary_private',\n\
                                                  'registry_notary_api')\n\
                       AND relation.relowner <> $1::bigint::oid\n\
                    ) AS relations_owned,\n\
                    NOT EXISTS (\n\
                      SELECT 1 FROM pg_catalog.pg_proc AS function\n\
                      JOIN pg_catalog.pg_namespace AS namespace\n\
                        ON namespace.oid = function.pronamespace\n\
                     WHERE namespace.nspname IN ('registry_notary_private',\n\
                                                  'registry_notary_api')\n\
                       AND function.proowner <> $1::bigint::oid\n\
                    ) AS functions_owned",
            &[&owner_oid],
        )
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    if !row_bool(&ownership, "schemas_owned")?
        || !row_bool(&ownership, "relations_owned")?
        || !row_bool(&ownership, "functions_owned")?
    {
        return Err(StatePlaneMigrationError::CapabilityDrift);
    }
    Ok(())
}

async fn attest_owner_metadata(
    client: &impl GenericClient,
    expected_roles: BoundRoleOids,
) -> Result<(), StatePlaneMigrationError> {
    if metadata_roles_for_exact_v1(client).await? != expected_roles {
        return Err(StatePlaneMigrationError::CapabilityDrift);
    }
    Ok(())
}

async fn attest_catalog_shape(
    client: &impl GenericClient,
    roles: BoundRoleOids,
    server_major: i32,
) -> Result<(), StatePlaneMigrationError> {
    let shape = client
        .query_one(
            "SELECT (\n\
                 SELECT count(*)::bigint\n\
                   FROM pg_catalog.pg_class AS relation\n\
                   JOIN pg_catalog.pg_namespace AS namespace\n\
                     ON namespace.oid = relation.relnamespace\n\
                  WHERE namespace.nspname = 'registry_notary_private'\n\
                    AND relation.relkind IN ('r', 'p')\n\
               ) AS private_table_count,\n\
               (\n\
                 SELECT count(*)::bigint\n\
                   FROM pg_catalog.pg_proc AS function\n\
                   JOIN pg_catalog.pg_namespace AS namespace\n\
                     ON namespace.oid = function.pronamespace\n\
                  WHERE namespace.nspname = 'registry_notary_api'\n\
               ) AS api_function_count,\n\
               (SELECT count(*) = 2 AND bool_and(namespace.nspowner = $1::bigint::oid)\n\
                  FROM pg_catalog.pg_namespace AS namespace\n\
                 WHERE namespace.nspname IN ('registry_notary_private',\n\
                                              'registry_notary_api')) AS schemas_owned,\n\
               NOT EXISTS (\n\
                 SELECT 1 FROM pg_catalog.pg_class AS relation\n\
                 JOIN pg_catalog.pg_namespace AS namespace\n\
                   ON namespace.oid = relation.relnamespace\n\
                WHERE namespace.nspname IN ('registry_notary_private',\n\
                                             'registry_notary_api')\n\
                  AND relation.relowner <> $1::bigint::oid\n\
               ) AS relations_owned,\n\
               NOT EXISTS (\n\
                 SELECT 1 FROM pg_catalog.pg_proc AS function\n\
                 JOIN pg_catalog.pg_namespace AS namespace\n\
                   ON namespace.oid = function.pronamespace\n\
                WHERE namespace.nspname IN ('registry_notary_private',\n\
                                             'registry_notary_api')\n\
                  AND function.proowner <> $1::bigint::oid\n\
               ) AS functions_owned,\n\
               NOT EXISTS (\n\
                 SELECT 1\n\
                   FROM pg_catalog.pg_namespace AS namespace\n\
                   CROSS JOIN LATERAL pg_catalog.aclexplode(\n\
                     COALESCE(namespace.nspacl,\n\
                       pg_catalog.acldefault('n', namespace.nspowner))) AS acl\n\
                  WHERE namespace.nspname IN ('registry_notary_private',\n\
                                               'registry_notary_api')\n\
                    AND acl.grantee = 0\n\
               ) AS public_schemas_denied,\n\
               (NOT EXISTS (\n\
                 SELECT 1\n\
                   FROM pg_catalog.pg_class AS relation\n\
                   JOIN pg_catalog.pg_namespace AS namespace\n\
                     ON namespace.oid = relation.relnamespace\n\
                   CROSS JOIN LATERAL pg_catalog.aclexplode(\n\
                     COALESCE(relation.relacl,\n\
                       pg_catalog.acldefault('r', relation.relowner))) AS acl\n\
                  WHERE namespace.nspname = 'registry_notary_private'\n\
                    AND relation.relkind IN ('r', 'p')\n\
                    AND acl.grantee = 0\n\
               ) AND NOT EXISTS (\n\
                 SELECT 1\n\
                   FROM pg_catalog.pg_class AS relation\n\
                   JOIN pg_catalog.pg_namespace AS namespace\n\
                     ON namespace.oid = relation.relnamespace\n\
                   CROSS JOIN LATERAL pg_catalog.aclexplode(\n\
                     COALESCE(relation.relacl,\n\
                       pg_catalog.acldefault('S', relation.relowner))) AS acl\n\
                  WHERE namespace.nspname = 'registry_notary_private'\n\
                    AND relation.relkind = 'S'\n\
                    AND acl.grantee = 0\n\
               )) AS public_relations_denied,\n\
               NOT pg_catalog.has_schema_privilege($2::bigint::oid,\n\
                   'registry_notary_private', 'USAGE')\n\
                 AND NOT pg_catalog.has_schema_privilege($2::bigint::oid,\n\
                   'registry_notary_private', 'CREATE') AS runtime_private_denied,\n\
               pg_catalog.has_schema_privilege($2::bigint::oid,\n\
                   'registry_notary_api', 'USAGE')\n\
                 AND NOT pg_catalog.has_schema_privilege($2::bigint::oid,\n\
                   'registry_notary_api', 'CREATE') AS runtime_api_allowed,\n\
               NOT EXISTS (\n\
                 SELECT 1\n\
                   FROM pg_catalog.pg_class AS relation\n\
                   JOIN pg_catalog.pg_namespace AS namespace\n\
                     ON namespace.oid = relation.relnamespace\n\
                  WHERE namespace.nspname = 'registry_notary_private'\n\
                    AND pg_catalog.has_table_privilege($2::bigint::oid, relation.oid,\n\
                        'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')\n\
               ) AS runtime_tables_denied,\n\
               (SELECT count(*) = $3\n\
                  FROM pg_catalog.pg_proc AS function\n\
                  JOIN pg_catalog.pg_namespace AS namespace\n\
                    ON namespace.oid = function.pronamespace\n\
                 WHERE namespace.nspname = 'registry_notary_api'\n\
                   AND pg_catalog.has_function_privilege($2::bigint::oid, function.oid, 'EXECUTE'))\n\
                 AS runtime_functions_exact,\n\
               NOT EXISTS (\n\
                 SELECT 1\n\
                   FROM pg_catalog.pg_proc AS function\n\
                   JOIN pg_catalog.pg_namespace AS namespace\n\
                     ON namespace.oid = function.pronamespace\n\
                   CROSS JOIN LATERAL pg_catalog.aclexplode(\n\
                     COALESCE(function.proacl,\n\
                       pg_catalog.acldefault('f', function.proowner))) AS acl\n\
                  WHERE namespace.nspname IN ('registry_notary_private',\n\
                                               'registry_notary_api')\n\
                    AND acl.grantee = 0\n\
                    AND acl.privilege_type = 'EXECUTE'\n\
               ) AS public_functions_denied,\n\
               (SELECT NOT owner.rolcanlogin AND NOT owner.rolsuper\n\
                         AND NOT owner.rolcreaterole AND NOT owner.rolcreatedb\n\
                         AND NOT owner.rolreplication AND NOT owner.rolbypassrls\n\
                  FROM pg_catalog.pg_roles AS owner\n\
                 WHERE owner.oid = $1::bigint::oid) AS owner_safe,\n\
               (SELECT runtime.rolcanlogin AND NOT runtime.rolsuper\n\
                         AND NOT runtime.rolcreaterole AND NOT runtime.rolcreatedb\n\
                         AND NOT runtime.rolreplication AND NOT runtime.rolbypassrls\n\
                         AND NOT pg_catalog.pg_has_role(runtime.oid,\n\
                             $1::bigint::oid, 'MEMBER')\n\
                  FROM pg_catalog.pg_roles AS runtime\n\
                 WHERE runtime.oid = $2::bigint::oid) AS runtime_safe",
            &[&roles.owner, &roles.runtime, &EXPECTED_API_FUNCTION_COUNT_V1],
        )
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    if row_i64(&shape, "private_table_count")? != EXPECTED_PRIVATE_TABLE_COUNT_V1
        || row_i64(&shape, "api_function_count")? != EXPECTED_API_FUNCTION_COUNT_V1
        || !row_bool(&shape, "schemas_owned")?
        || !row_bool(&shape, "relations_owned")?
        || !row_bool(&shape, "functions_owned")?
        || !row_bool(&shape, "public_schemas_denied")?
        || !row_bool(&shape, "public_relations_denied")?
        || !row_bool(&shape, "runtime_private_denied")?
        || !row_bool(&shape, "runtime_api_allowed")?
        || !row_bool(&shape, "runtime_tables_denied")?
        || !row_bool(&shape, "runtime_functions_exact")?
        || !row_bool(&shape, "public_functions_denied")?
        || !row_bool(&shape, "owner_safe")?
        || !row_bool(&shape, "runtime_safe")?
    {
        return Err(StatePlaneMigrationError::CapabilityDrift);
    }
    let observed = catalog_definition_fingerprint(client).await?;
    if observed != expected_catalog_definition_fingerprint(server_major)? {
        return Err(StatePlaneMigrationError::CapabilityDrift);
    }
    Ok(())
}

async fn catalog_definition_fingerprint(
    client: &impl GenericClient,
) -> Result<String, StatePlaneMigrationError> {
    let row = client
        .query_one(CATALOG_DEFINITION_QUERY_V1, &[])
        .await
        .map_err(|_| StatePlaneMigrationError::Unavailable)?;
    let mut hasher = Sha256::new();
    for field in ["columns", "constraints", "indexes", "functions"] {
        let contract: String = row
            .try_get(field)
            .map_err(|_| StatePlaneMigrationError::CapabilityDrift)?;
        hasher.update(field.as_bytes());
        hasher.update([0]);
        hasher.update(contract.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

fn expected_catalog_definition_fingerprint(
    server_major: i32,
) -> Result<&'static str, StatePlaneMigrationError> {
    match server_major {
        16 => Ok(EXPECTED_CATALOG_DEFINITION_FINGERPRINT_PG16_V1),
        17 => Ok(EXPECTED_CATALOG_DEFINITION_FINGERPRINT_PG17_V1),
        18 => Ok(EXPECTED_CATALOG_DEFINITION_FINGERPRINT_PG18_V1),
        _ => Err(StatePlaneMigrationError::UnsupportedServerMajor),
    }
}

fn expected_previous_catalog_definition_fingerprint(
    server_major: i32,
) -> Result<&'static str, StatePlaneMigrationError> {
    match server_major {
        16 => Ok(PREVIOUS_CATALOG_DEFINITION_FINGERPRINT_PG16_V1),
        17 => Ok(PREVIOUS_CATALOG_DEFINITION_FINGERPRINT_PG17_V1),
        18 => Ok(PREVIOUS_CATALOG_DEFINITION_FINGERPRINT_PG18_V1),
        _ => Err(StatePlaneMigrationError::UnsupportedServerMajor),
    }
}

// These fingerprints are derived from the deterministic catalog projection
// below and are pinned separately for every supported PostgreSQL major.
const EXPECTED_CATALOG_DEFINITION_FINGERPRINT_PG16_V1: &str =
    "2ead81e377f2781032e933be2934d55e9253506e0de7435eb851e34bb74aa589";
const EXPECTED_CATALOG_DEFINITION_FINGERPRINT_PG17_V1: &str =
    "2ead81e377f2781032e933be2934d55e9253506e0de7435eb851e34bb74aa589";
const EXPECTED_CATALOG_DEFINITION_FINGERPRINT_PG18_V1: &str =
    "b96c69fe23f974815880668079a57c156e957a66144c5882c63a0712f29be89d";
const PREVIOUS_CATALOG_DEFINITION_FINGERPRINT_PG16_V1: &str =
    "cf45576aced8a825cd2891800f2636ec1ca0dd0959b81f3a787cc0ed36ea09a5";
const PREVIOUS_CATALOG_DEFINITION_FINGERPRINT_PG17_V1: &str =
    "cf45576aced8a825cd2891800f2636ec1ca0dd0959b81f3a787cc0ed36ea09a5";
const PREVIOUS_CATALOG_DEFINITION_FINGERPRINT_PG18_V1: &str =
    "81760fbb2d3839783503774b3e6b436187c1969a154a331929d097e0e654eea2";

const CATALOG_DEFINITION_QUERY_V1: &str = r#"
SELECT COALESCE((
         SELECT pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_array(
                        namespace.nspname,
                        relation.relname,
                        relation.relkind,
                        relation.relpersistence,
                        attribute.attnum,
                        attribute.attname,
                        pg_catalog.format_type(attribute.atttypid, attribute.atttypmod),
                        attribute.attnotnull,
                        attribute.attidentity,
                        attribute.attgenerated,
                        COALESCE(collation_record.collname, ''),
                        COALESCE(pg_catalog.pg_get_expr(default_value.adbin,
                            default_value.adrelid, FALSE), '')
                    ) ORDER BY namespace.nspname, relation.relname, attribute.attnum
                )::text
           FROM pg_catalog.pg_class AS relation
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = relation.relnamespace
           JOIN pg_catalog.pg_attribute AS attribute
             ON attribute.attrelid = relation.oid
            AND attribute.attnum > 0
            AND NOT attribute.attisdropped
           LEFT JOIN pg_catalog.pg_attrdef AS default_value
             ON default_value.adrelid = relation.oid
            AND default_value.adnum = attribute.attnum
           LEFT JOIN pg_catalog.pg_collation AS collation_record
             ON collation_record.oid = attribute.attcollation
          WHERE namespace.nspname = 'registry_notary_private'
            AND relation.relkind IN ('r', 'p')
       ), '[]') AS columns,
       COALESCE((
         SELECT pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_array(
                        namespace.nspname,
                        relation.relname,
                        constraint_record.conname,
                        constraint_record.contype,
                        constraint_record.condeferrable,
                        constraint_record.condeferred,
                        constraint_record.convalidated,
                        pg_catalog.pg_get_constraintdef(constraint_record.oid, FALSE)
                    ) ORDER BY namespace.nspname, relation.relname,
                               constraint_record.conname
                )::text
           FROM pg_catalog.pg_constraint AS constraint_record
           JOIN pg_catalog.pg_class AS relation
             ON relation.oid = constraint_record.conrelid
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = relation.relnamespace
          WHERE namespace.nspname = 'registry_notary_private'
       ), '[]') AS constraints,
       COALESCE((
         SELECT pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_array(
                        namespace.nspname,
                        relation.relname,
                        index_relation.relname,
                        pg_catalog.pg_get_indexdef(index_record.indexrelid, 0, FALSE)
                    ) ORDER BY namespace.nspname, relation.relname,
                               index_relation.relname
                )::text
           FROM pg_catalog.pg_index AS index_record
           JOIN pg_catalog.pg_class AS relation
             ON relation.oid = index_record.indrelid
           JOIN pg_catalog.pg_class AS index_relation
             ON index_relation.oid = index_record.indexrelid
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = relation.relnamespace
          WHERE namespace.nspname = 'registry_notary_private'
       ), '[]') AS indexes,
       COALESCE((
         SELECT pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_array(
                        namespace.nspname,
                        function_record.proname,
                        pg_catalog.pg_get_function_identity_arguments(function_record.oid),
                        pg_catalog.pg_get_function_result(function_record.oid),
                        language.lanname,
                        function_record.prosecdef,
                        function_record.provolatile,
                        function_record.proisstrict,
                        COALESCE(function_record.proconfig::text, ''),
                        function_record.prosrc
                    ) ORDER BY namespace.nspname, function_record.proname,
                               pg_catalog.pg_get_function_identity_arguments(function_record.oid)
                )::text
           FROM pg_catalog.pg_proc AS function_record
           JOIN pg_catalog.pg_namespace AS namespace
             ON namespace.oid = function_record.pronamespace
           JOIN pg_catalog.pg_language AS language
             ON language.oid = function_record.prolang
          WHERE namespace.nspname IN ('registry_notary_private', 'registry_notary_api')
       ), '[]') AS functions
"#;

fn row_bool(row: &Row, name: &'static str) -> Result<bool, StatePlaneMigrationError> {
    row.try_get(name)
        .map_err(|_| StatePlaneMigrationError::CapabilityDrift)
}

fn row_i32(row: &Row, name: &'static str) -> Result<i32, StatePlaneMigrationError> {
    row.try_get(name)
        .map_err(|_| StatePlaneMigrationError::CapabilityDrift)
}

fn row_i64(row: &Row, name: &'static str) -> Result<i64, StatePlaneMigrationError> {
    row.try_get(name)
        .map_err(|_| StatePlaneMigrationError::CapabilityDrift)
}

pub const POSTGRES_STATE_PLANE_MIGRATION_V1: &str =
    concat!("\n", include_str!("migration/postgres_state_plane_v1.sql"));

#[cfg(test)]
#[path = "migration/tests.rs"]
mod tests;
