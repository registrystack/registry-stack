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
    "nonce=keyed-reserve-consume-sixty-second-tombstone-v1\0",
    "evaluation=client-bound-stored-record-v2-atomic-publication-expiry-v1\0",
    "batch=keyed-request-owner-lease-quota-once-takeover-atomic-completion-stored-response-v2-fifteen-minute-retention-v1\0",
    "credential-status=insert-only-locked-transition-terminal-revocation-expiry-retention-monotonic-updated-at-v1\0",
    "machine-quota=keyed-principal-fixed-minute-whole-cost-atomic-v1\0",
    "subject-access-quota=keyed-pseudonym-six-closed-buckets-fixed-windows-canonical-lock-order-caller-denial-order-atomic-all-or-none-check-only-no-mutation-v1\0",
    "preauthorization-login=keyed-state-capacity-4096-encrypted-single-consume-expiry-v1\0",
    "preauthorization-tx-code=keyed-jti-keyed-pin-verifier-peek-redeem-with-replay-one-winner-expiry-v1\0",
    "retention=bounded-expiry-prune-skip-locked-v1\0",
);
pub const STATE_PLANE_SCHEMA_FINGERPRINT_V1: &str =
    "786d9bc5192fc0a11bf9e298b5612bd66233ddd877b65ee32ed70ff5905faea2";

const MIGRATION_ADVISORY_LOCK_KEY_V1: i64 = 0x4e4f_5441_5259_0001;
const EXPECTED_PRIVATE_TABLE_COUNT_V1: i64 = 10;
const EXPECTED_API_FUNCTION_COUNT_V1: i64 = 23;

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
            rebind_restored_metadata(&transaction, role_oids, runtime_role, server_major).await?;
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
    if capability != STATE_PLANE_CAPABILITY_V1
        || schema_version != STATE_PLANE_SCHEMA_VERSION_V1
        || fingerprint != STATE_PLANE_SCHEMA_FINGERPRINT_V1
        || row_i64(&row, "caller_role_oid")? != roles.runtime
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
         GRANT EXECUTE ON FUNCTION registry_notary_api.nonce_consume_v1(bytea, bytea) TO {role};\n\
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
         GRANT EXECUTE ON FUNCTION registry_notary_api.preauthorization_redeem_v1(bytea, bytea, timestamptz, boolean, bytea) TO {role};\n\
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
    attest_restored_catalog_ownership(transaction, roles.owner, server_major).await?;
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

async fn attest_restored_catalog_ownership(
    client: &impl GenericClient,
    owner_oid: i64,
    server_major: i32,
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
    let observed = catalog_definition_fingerprint(client).await?;
    if observed != expected_catalog_definition_fingerprint(server_major)? {
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

// These fingerprints are derived from the deterministic catalog projection
// below and are pinned separately for every supported PostgreSQL major.
const EXPECTED_CATALOG_DEFINITION_FINGERPRINT_PG16_V1: &str =
    "ad2a1f3101bd9c68cd1f0eb840a832335da76ef0ce0d61abdcd443e786db47a1";
const EXPECTED_CATALOG_DEFINITION_FINGERPRINT_PG17_V1: &str =
    "ad2a1f3101bd9c68cd1f0eb840a832335da76ef0ce0d61abdcd443e786db47a1";
const EXPECTED_CATALOG_DEFINITION_FINGERPRINT_PG18_V1: &str =
    "7daa60e883a4e1fe5bab97590d74039da7c63e306e52e17b39baf2460d2f60c9";

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

pub const POSTGRES_STATE_PLANE_MIGRATION_V1: &str = r#"
CREATE SCHEMA registry_notary_private AUTHORIZATION CURRENT_USER;
CREATE SCHEMA registry_notary_api AUTHORIZATION CURRENT_USER;

REVOKE ALL ON SCHEMA registry_notary_private FROM PUBLIC;
REVOKE ALL ON SCHEMA registry_notary_api FROM PUBLIC;

CREATE TABLE registry_notary_private.schema_metadata (
    singleton boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    capability_id text NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version > 0),
    schema_fingerprint text NOT NULL CHECK (schema_fingerprint ~ '^[0-9a-f]{64}$'),
    owner_role_oid oid NOT NULL,
    runtime_role_oid oid NOT NULL,
    installed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    CHECK (owner_role_oid <> runtime_role_oid)
);

CREATE TABLE registry_notary_private.replay_identifier (
    scope_hash bytea NOT NULL CHECK (pg_catalog.octet_length(scope_hash) = 32),
    identifier_hash bytea NOT NULL CHECK (pg_catalog.octet_length(identifier_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (scope_hash, identifier_hash),
    CHECK (expires_at > created_at)
);
CREATE INDEX replay_identifier_expiry_idx
    ON registry_notary_private.replay_identifier (expires_at);

CREATE TABLE registry_notary_private.consumable_nonce (
    scope_hash bytea NOT NULL CHECK (pg_catalog.octet_length(scope_hash) = 32),
    nonce_hash bytea NOT NULL CHECK (pg_catalog.octet_length(nonce_hash) = 32),
    state text NOT NULL CHECK (state IN ('reserved', 'consumed')),
    reservation_expires_at timestamptz NOT NULL,
    tombstone_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (scope_hash, nonce_hash),
    CHECK (
        (state = 'reserved' AND tombstone_expires_at IS NULL)
        OR (state = 'consumed' AND tombstone_expires_at IS NOT NULL)
    )
);
CREATE INDEX consumable_nonce_retention_idx
    ON registry_notary_private.consumable_nonce (
        (CASE WHEN state = 'reserved' THEN reservation_expires_at ELSE tombstone_expires_at END)
    );

CREATE TABLE registry_notary_private.evaluation (
    evaluation_id text PRIMARY KEY CHECK (pg_catalog.length(evaluation_id) BETWEEN 1 AND 256),
    client_id_hash bytea NOT NULL CHECK (pg_catalog.octet_length(client_id_hash) = 32),
    request_hash bytea NOT NULL CHECK (pg_catalog.octet_length(request_hash) = 32),
    purpose text NOT NULL CHECK (pg_catalog.length(purpose) BETWEEN 1 AND 256),
    record_version smallint NOT NULL CHECK (record_version = 2),
    record_json jsonb NOT NULL CHECK (pg_catalog.jsonb_typeof(record_json) = 'object'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);
CREATE INDEX evaluation_client_expiry_idx
    ON registry_notary_private.evaluation (client_id_hash, expires_at);
CREATE INDEX evaluation_expiry_idx
    ON registry_notary_private.evaluation (expires_at);

CREATE TABLE registry_notary_private.batch_idempotency (
    key_hash bytea PRIMARY KEY CHECK (pg_catalog.octet_length(key_hash) = 32),
    request_hash bytea NOT NULL CHECK (pg_catalog.octet_length(request_hash) = 32),
    principal_hash bytea NOT NULL CHECK (pg_catalog.octet_length(principal_hash) = 32),
    state text NOT NULL CHECK (state IN ('in_flight', 'completed', 'failed')),
    owner_token bytea CHECK (owner_token IS NULL OR pg_catalog.octet_length(owner_token) = 32),
    lease_expires_at timestamptz,
    quota_charged boolean NOT NULL,
    response_version smallint,
    response_json jsonb,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    retention_expires_at timestamptz NOT NULL,
    CHECK (
        (state = 'in_flight' AND owner_token IS NOT NULL AND lease_expires_at IS NOT NULL
            AND response_version IS NULL AND response_json IS NULL)
        OR (state = 'completed' AND owner_token IS NULL AND lease_expires_at IS NULL
            AND response_version = 2 AND pg_catalog.jsonb_typeof(response_json) = 'object')
        OR (state = 'failed' AND owner_token IS NULL AND lease_expires_at IS NULL
            AND response_version IS NULL AND response_json IS NULL)
    )
);
CREATE INDEX batch_idempotency_retention_idx
    ON registry_notary_private.batch_idempotency (retention_expires_at);
CREATE INDEX batch_idempotency_lease_idx
    ON registry_notary_private.batch_idempotency (lease_expires_at)
    WHERE state = 'in_flight';

CREATE TABLE registry_notary_private.credential_status (
    credential_id text PRIMARY KEY CHECK (pg_catalog.length(credential_id) BETWEEN 1 AND 512),
    issuer text NOT NULL CHECK (pg_catalog.length(issuer) BETWEEN 1 AND 2048),
    profile text NOT NULL CHECK (pg_catalog.length(profile) BETWEEN 1 AND 256),
    status text NOT NULL CHECK (status IN ('valid', 'suspended', 'revoked')),
    issued_at timestamptz NOT NULL,
    credential_expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    purge_after timestamptz NOT NULL,
    CHECK (credential_expires_at > issued_at),
    CHECK (purge_after > credential_expires_at),
    CHECK (updated_at >= issued_at)
);
CREATE INDEX credential_status_purge_idx
    ON registry_notary_private.credential_status (purge_after);

CREATE TABLE registry_notary_private.machine_quota (
    principal_hash bytea PRIMARY KEY CHECK (pg_catalog.octet_length(principal_hash) = 32),
    window_started_at timestamptz NOT NULL,
    window_expires_at timestamptz NOT NULL,
    used integer NOT NULL CHECK (used >= 0),
    CHECK (window_expires_at > window_started_at)
);
CREATE INDEX machine_quota_expiry_idx
    ON registry_notary_private.machine_quota (window_expires_at);

CREATE TABLE registry_notary_private.subject_access_quota (
    bucket_kind text NOT NULL CHECK (bucket_kind IN (
        'invalid_token_per_client_address',
        'per_principal',
        'subject_mismatch_per_principal',
        'per_holder_issuance',
        'credential_issuance_per_principal',
        'tx_code_attempt_per_code'
    )),
    key_hash bytea NOT NULL CHECK (pg_catalog.octet_length(key_hash) = 32),
    window_started_at timestamptz NOT NULL,
    window_expires_at timestamptz NOT NULL,
    used integer NOT NULL CHECK (used >= 0),
    PRIMARY KEY (bucket_kind, key_hash),
    CHECK (window_expires_at > window_started_at)
);
CREATE INDEX subject_access_quota_expiry_idx
    ON registry_notary_private.subject_access_quota (window_expires_at);

CREATE TABLE registry_notary_private.preauthorization_login_state (
    state_hash bytea PRIMARY KEY CHECK (pg_catalog.octet_length(state_hash) = 32),
    credential_configuration_id text NOT NULL
        CHECK (pg_catalog.length(credential_configuration_id) BETWEEN 1 AND 256),
    key_id bytea NOT NULL CHECK (pg_catalog.octet_length(key_id) = 32),
    aead_nonce bytea NOT NULL CHECK (pg_catalog.octet_length(aead_nonce) BETWEEN 12 AND 24),
    ciphertext bytea NOT NULL CHECK (pg_catalog.octet_length(ciphertext) BETWEEN 17 AND 8192),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);
CREATE INDEX preauthorization_login_state_expiry_idx
    ON registry_notary_private.preauthorization_login_state (expires_at);

CREATE TABLE registry_notary_private.preauthorization_tx_code (
    jti_hash bytea PRIMARY KEY CHECK (pg_catalog.octet_length(jti_hash) = 32),
    key_id bytea NOT NULL CHECK (pg_catalog.octet_length(key_id) = 32),
    pin_verifier bytea NOT NULL CHECK (pg_catalog.octet_length(pin_verifier) = 32),
    pin_length smallint NOT NULL CHECK (pin_length BETWEEN 4 AND 12),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);
CREATE INDEX preauthorization_tx_code_expiry_idx
    ON registry_notary_private.preauthorization_tx_code (expires_at);

ALTER DEFAULT PRIVILEGES IN SCHEMA registry_notary_private
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA registry_notary_private
    REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA registry_notary_api
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE FUNCTION registry_notary_api.attest_v1()
RETURNS TABLE (
    capability_id text,
    schema_version integer,
    schema_fingerprint text,
    owner_role_oid bigint,
    runtime_role_oid bigint,
    caller_role_oid bigint,
    server_major integer,
    database_writable boolean,
    durability_safe boolean
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT metadata.capability_id,
           metadata.schema_version,
           metadata.schema_fingerprint,
           metadata.owner_role_oid::bigint,
           metadata.runtime_role_oid::bigint,
           caller.oid::bigint,
           current_setting('server_version_num')::integer / 10000,
           NOT pg_catalog.pg_is_in_recovery()
             AND NOT current_setting('transaction_read_only')::boolean,
           current_setting('fsync') = 'on'
             AND current_setting('synchronous_commit') = 'on'
             AND current_setting('full_page_writes') = 'on'
      FROM registry_notary_private.schema_metadata AS metadata
      JOIN pg_catalog.pg_roles AS caller ON caller.rolname = session_user
     WHERE metadata.singleton
$function$;

CREATE FUNCTION registry_notary_api.readiness_v1()
RETURNS TABLE (
    capability_id text,
    schema_version integer,
    schema_fingerprint text,
    owner_role_oid bigint,
    runtime_role_oid bigint,
    caller_role_oid bigint,
    server_major integer,
    database_writable boolean,
    durability_safe boolean
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT * FROM registry_notary_api.attest_v1()
$function$;

CREATE FUNCTION registry_notary_api.replay_insert_v1(
    p_scope_hash bytea,
    p_identifier_hash bytea,
    p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
BEGIN
    IF pg_catalog.octet_length(p_scope_hash) <> 32
       OR pg_catalog.octet_length(p_identifier_hash) <> 32
       OR p_expires_at <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid replay input';
    END IF;

    INSERT INTO registry_notary_private.replay_identifier (
        scope_hash, identifier_hash, created_at, expires_at
    ) VALUES (p_scope_hash, p_identifier_hash, v_now, p_expires_at)
    ON CONFLICT (scope_hash, identifier_hash) DO UPDATE
       SET created_at = EXCLUDED.created_at,
           expires_at = EXCLUDED.expires_at
     WHERE registry_notary_private.replay_identifier.expires_at <= v_now;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.nonce_reserve_v1(
    p_scope_hash bytea,
    p_nonce_hash bytea,
    p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
BEGIN
    IF pg_catalog.octet_length(p_scope_hash) <> 32
       OR pg_catalog.octet_length(p_nonce_hash) <> 32
       OR p_expires_at <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid nonce input';
    END IF;

    INSERT INTO registry_notary_private.consumable_nonce (
        scope_hash, nonce_hash, state, reservation_expires_at,
        tombstone_expires_at, created_at, updated_at
    ) VALUES (
        p_scope_hash, p_nonce_hash, 'reserved', p_expires_at,
        NULL, v_now, v_now
    )
    ON CONFLICT (scope_hash, nonce_hash) DO UPDATE
       SET state = 'reserved',
           reservation_expires_at = EXCLUDED.reservation_expires_at,
           tombstone_expires_at = NULL,
           created_at = EXCLUDED.created_at,
           updated_at = EXCLUDED.updated_at
     WHERE (
         registry_notary_private.consumable_nonce.state = 'reserved'
         AND registry_notary_private.consumable_nonce.reservation_expires_at <= v_now
     ) OR (
         registry_notary_private.consumable_nonce.state = 'consumed'
         AND registry_notary_private.consumable_nonce.tombstone_expires_at <= v_now
     );
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.nonce_consume_v1(
    p_scope_hash bytea,
    p_nonce_hash bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
BEGIN
    IF pg_catalog.octet_length(p_scope_hash) <> 32
       OR pg_catalog.octet_length(p_nonce_hash) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid nonce input';
    END IF;

    UPDATE registry_notary_private.consumable_nonce
       SET state = 'consumed',
           tombstone_expires_at = v_now + interval '60 seconds',
           updated_at = v_now
     WHERE scope_hash = p_scope_hash
       AND nonce_hash = p_nonce_hash
       AND state = 'reserved'
       AND reservation_expires_at > v_now;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.evaluation_insert_v1(
    p_evaluation_id text,
    p_client_id_hash bytea,
    p_request_hash bytea,
    p_purpose text,
    p_record_version smallint,
    p_record_json jsonb,
    p_created_at timestamptz,
    p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_count bigint;
BEGIN
    INSERT INTO registry_notary_private.evaluation (
        evaluation_id, client_id_hash, request_hash, purpose, record_version,
        record_json, created_at, expires_at
    ) VALUES (
        p_evaluation_id, p_client_id_hash, p_request_hash, p_purpose,
        p_record_version, p_record_json, p_created_at, p_expires_at
    ) ON CONFLICT (evaluation_id) DO NOTHING;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.evaluation_get_v1(
    p_evaluation_id text,
    p_client_id_hash bytea
)
RETURNS TABLE (
    record_version smallint,
    record_json jsonb,
    created_at timestamptz,
    expires_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT evaluation.record_version,
           evaluation.record_json,
           evaluation.created_at,
           evaluation.expires_at
      FROM registry_notary_private.evaluation AS evaluation
     WHERE evaluation.evaluation_id = p_evaluation_id
       AND evaluation.client_id_hash = p_client_id_hash
       AND evaluation.expires_at > pg_catalog.clock_timestamp()
$function$;

CREATE FUNCTION registry_notary_api.batch_reserve_v1(
    p_key_hash bytea,
    p_request_hash bytea,
    p_principal_hash bytea,
    p_owner_token bytea,
    p_lease_seconds integer,
    p_quota_limit integer,
    p_quota_cost integer
)
RETURNS TABLE (
    outcome text,
    retry_after_seconds bigint,
    lease_expires_at timestamptz,
    response_version smallint,
    response_json jsonb
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_inserted bigint;
    v_fresh boolean;
    v_idempotency registry_notary_private.batch_idempotency%ROWTYPE;
    v_quota registry_notary_private.machine_quota%ROWTYPE;
BEGIN
    IF pg_catalog.octet_length(p_key_hash) <> 32
       OR pg_catalog.octet_length(p_request_hash) <> 32
       OR pg_catalog.octet_length(p_principal_hash) <> 32
       OR pg_catalog.octet_length(p_owner_token) <> 32
       OR p_lease_seconds NOT BETWEEN 1 AND 300
       OR p_quota_cost <= 0
       OR (p_quota_limit IS NOT NULL AND p_quota_limit <= 0) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid idempotency input';
    END IF;

    INSERT INTO registry_notary_private.batch_idempotency (
        key_hash, request_hash, principal_hash, state, owner_token,
        lease_expires_at, quota_charged, created_at, updated_at,
        retention_expires_at
    ) VALUES (
        p_key_hash, p_request_hash, p_principal_hash, 'in_flight', p_owner_token,
        v_now + pg_catalog.make_interval(secs => p_lease_seconds), FALSE,
        v_now, v_now, v_now + interval '15 minutes'
    ) ON CONFLICT (key_hash) DO NOTHING;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    v_fresh := v_inserted = 1;

    SELECT * INTO STRICT v_idempotency
      FROM registry_notary_private.batch_idempotency
     WHERE key_hash = p_key_hash
     FOR UPDATE;

    IF NOT v_fresh AND v_idempotency.retention_expires_at <= v_now THEN
        v_fresh := TRUE;
    ELSIF NOT v_fresh AND v_idempotency.request_hash <> p_request_hash THEN
        RETURN QUERY SELECT 'conflict'::text, NULL::bigint, NULL::timestamptz,
                            NULL::smallint, NULL::jsonb;
        RETURN;
    ELSIF NOT v_fresh AND v_idempotency.state = 'completed' THEN
        RETURN QUERY SELECT 'replay'::text, 0::bigint, NULL::timestamptz,
                            v_idempotency.response_version, v_idempotency.response_json;
        RETURN;
    ELSIF NOT v_fresh AND v_idempotency.state = 'in_flight'
          AND v_idempotency.lease_expires_at > v_now THEN
        RETURN QUERY SELECT 'wait'::text,
            GREATEST(1::bigint, CEIL(EXTRACT(EPOCH FROM
                (v_idempotency.lease_expires_at - v_now)))::bigint),
            v_idempotency.lease_expires_at, NULL::smallint, NULL::jsonb;
        RETURN;
    ELSIF NOT v_fresh THEN
        UPDATE registry_notary_private.batch_idempotency
           SET state = 'in_flight',
               owner_token = p_owner_token,
               lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds),
               response_version = NULL,
               response_json = NULL,
               updated_at = v_now,
               retention_expires_at = v_now + interval '15 minutes'
         WHERE key_hash = p_key_hash;
        RETURN QUERY SELECT 'owner'::text, 0::bigint,
            v_now + pg_catalog.make_interval(secs => p_lease_seconds),
            NULL::smallint, NULL::jsonb;
        RETURN;
    END IF;

    IF p_quota_limit IS NOT NULL THEN
        INSERT INTO registry_notary_private.machine_quota (
            principal_hash, window_started_at, window_expires_at, used
        ) VALUES (p_principal_hash, v_now, v_now + interval '1 minute', 0)
        ON CONFLICT (principal_hash) DO NOTHING;

        SELECT * INTO STRICT v_quota
          FROM registry_notary_private.machine_quota
         WHERE principal_hash = p_principal_hash
         FOR UPDATE;
        IF v_quota.window_expires_at <= v_now THEN
            UPDATE registry_notary_private.machine_quota
               SET window_started_at = v_now,
                   window_expires_at = v_now + interval '1 minute',
                   used = 0
             WHERE principal_hash = p_principal_hash;
            v_quota.window_expires_at := v_now + interval '1 minute';
            v_quota.used := 0;
        END IF;
        IF p_quota_cost > p_quota_limit - v_quota.used THEN
            DELETE FROM registry_notary_private.batch_idempotency
             WHERE key_hash = p_key_hash;
            RETURN QUERY SELECT 'quota_exceeded'::text,
                GREATEST(1::bigint, CEIL(EXTRACT(EPOCH FROM
                    (v_quota.window_expires_at - v_now)))::bigint),
                NULL::timestamptz, NULL::smallint, NULL::jsonb;
            RETURN;
        END IF;
        UPDATE registry_notary_private.machine_quota
           SET used = used + p_quota_cost
         WHERE principal_hash = p_principal_hash;
    END IF;

    UPDATE registry_notary_private.batch_idempotency
       SET request_hash = p_request_hash,
           principal_hash = p_principal_hash,
           state = 'in_flight',
           owner_token = p_owner_token,
           lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds),
           quota_charged = p_quota_limit IS NOT NULL,
           response_version = NULL,
           response_json = NULL,
           created_at = v_now,
           updated_at = v_now,
           retention_expires_at = v_now + interval '15 minutes'
     WHERE key_hash = p_key_hash;

    RETURN QUERY SELECT 'owner'::text, 0::bigint,
        v_now + pg_catalog.make_interval(secs => p_lease_seconds),
        NULL::smallint, NULL::jsonb;
END
$function$;

CREATE FUNCTION registry_notary_api.batch_heartbeat_v1(
    p_key_hash bytea,
    p_request_hash bytea,
    p_owner_token bytea,
    p_lease_seconds integer
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_count bigint;
BEGIN
    IF p_lease_seconds NOT BETWEEN 1 AND 300 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid lease';
    END IF;
    UPDATE registry_notary_private.batch_idempotency
       SET lease_expires_at = pg_catalog.clock_timestamp()
                              + pg_catalog.make_interval(secs => p_lease_seconds),
           updated_at = pg_catalog.clock_timestamp()
     WHERE key_hash = p_key_hash
       AND request_hash = p_request_hash
       AND state = 'in_flight'
       AND owner_token = p_owner_token;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.batch_complete_v1(
    p_key_hash bytea,
    p_request_hash bytea,
    p_owner_token bytea,
    p_evaluations jsonb,
    p_response_version smallint,
    p_response_json jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_idempotency registry_notary_private.batch_idempotency%ROWTYPE;
BEGIN
    IF p_response_version <> 2
       OR pg_catalog.jsonb_typeof(p_response_json) <> 'object'
       OR pg_catalog.jsonb_typeof(p_evaluations) <> 'array'
       OR pg_catalog.jsonb_array_length(p_evaluations) > 1024 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid completion';
    END IF;
    SELECT * INTO v_idempotency
      FROM registry_notary_private.batch_idempotency
     WHERE key_hash = p_key_hash
     FOR UPDATE;
    IF NOT FOUND
       OR v_idempotency.request_hash <> p_request_hash
       OR v_idempotency.state <> 'in_flight'
       OR v_idempotency.owner_token <> p_owner_token THEN
        RETURN FALSE;
    END IF;

    INSERT INTO registry_notary_private.evaluation (
        evaluation_id, client_id_hash, request_hash, purpose, record_version,
        record_json, created_at, expires_at
    )
    SELECT item->>'evaluation_id',
           pg_catalog.decode(item->>'client_id_hash_hex', 'hex'),
           p_request_hash,
           item->>'purpose',
           (item->>'record_version')::smallint,
           item->'record',
           (item->>'created_at')::timestamptz,
           (item->>'expires_at')::timestamptz
      FROM pg_catalog.jsonb_array_elements(p_evaluations) AS item;

    UPDATE registry_notary_private.batch_idempotency
       SET state = 'completed',
           owner_token = NULL,
           lease_expires_at = NULL,
           response_version = p_response_version,
           response_json = p_response_json,
           updated_at = v_now,
           retention_expires_at = v_now + interval '15 minutes'
     WHERE key_hash = p_key_hash;
    RETURN TRUE;
END
$function$;

CREATE FUNCTION registry_notary_api.batch_fail_v1(
    p_key_hash bytea,
    p_request_hash bytea,
    p_owner_token bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_count bigint;
    v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    UPDATE registry_notary_private.batch_idempotency
       SET state = 'failed',
           owner_token = NULL,
           lease_expires_at = NULL,
           updated_at = v_now,
           retention_expires_at = v_now + interval '15 minutes'
     WHERE key_hash = p_key_hash
       AND request_hash = p_request_hash
       AND state = 'in_flight'
       AND owner_token = p_owner_token;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.credential_status_insert_v1(
    p_credential_id text,
    p_issuer text,
    p_profile text,
    p_issued_at timestamptz,
    p_credential_expires_at timestamptz,
    p_retention_seconds integer
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_count bigint;
BEGIN
    IF p_retention_seconds <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid status retention';
    END IF;
    INSERT INTO registry_notary_private.credential_status (
        credential_id, issuer, profile, status, issued_at,
        credential_expires_at, updated_at, purge_after
    ) VALUES (
        p_credential_id, p_issuer, p_profile, 'valid', p_issued_at,
        p_credential_expires_at, p_issued_at,
        p_credential_expires_at + pg_catalog.make_interval(secs => p_retention_seconds)
    ) ON CONFLICT (credential_id) DO NOTHING;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.credential_status_get_v1(
    p_credential_id text
)
RETURNS TABLE (
    credential_id text,
    issuer text,
    profile text,
    status text,
    issued_at timestamptz,
    credential_expires_at timestamptz,
    updated_at timestamptz,
    purge_after timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT stored.credential_id,
           stored.issuer,
           stored.profile,
           stored.status,
           stored.issued_at,
           stored.credential_expires_at,
           stored.updated_at,
           stored.purge_after
      FROM registry_notary_private.credential_status AS stored
     WHERE stored.credential_id = p_credential_id
       AND stored.purge_after > pg_catalog.clock_timestamp()
$function$;

CREATE FUNCTION registry_notary_api.credential_status_update_v1(
    p_credential_id text,
    p_status text
)
RETURNS TABLE (
    outcome text,
    credential_id text,
    issuer text,
    profile text,
    status text,
    issued_at timestamptz,
    credential_expires_at timestamptz,
    updated_at timestamptz,
    purge_after timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_stored registry_notary_private.credential_status%ROWTYPE;
BEGIN
    IF p_status NOT IN ('valid', 'suspended', 'revoked') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid credential status';
    END IF;
    SELECT * INTO v_stored
      FROM registry_notary_private.credential_status AS stored
     WHERE stored.credential_id = p_credential_id
       AND stored.purge_after > v_now
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'not_found'::text, NULL::text, NULL::text, NULL::text,
                            NULL::text, NULL::timestamptz, NULL::timestamptz,
                            NULL::timestamptz, NULL::timestamptz;
        RETURN;
    END IF;
    IF v_stored.status = 'revoked' AND p_status <> 'revoked' THEN
        RETURN QUERY SELECT 'invalid_transition'::text,
            v_stored.credential_id, v_stored.issuer, v_stored.profile,
            v_stored.status, v_stored.issued_at, v_stored.credential_expires_at,
            v_stored.updated_at, v_stored.purge_after;
        RETURN;
    END IF;
    UPDATE registry_notary_private.credential_status AS stored
       SET status = p_status,
           updated_at = CASE
               WHEN v_now > stored.updated_at THEN v_now
               ELSE stored.updated_at
           END
     WHERE stored.credential_id = p_credential_id
     RETURNING stored.* INTO v_stored;
    RETURN QUERY SELECT 'updated'::text,
        v_stored.credential_id, v_stored.issuer, v_stored.profile,
        v_stored.status, v_stored.issued_at, v_stored.credential_expires_at,
        v_stored.updated_at, v_stored.purge_after;
END
$function$;

CREATE FUNCTION registry_notary_api.machine_quota_debit_v1(
    p_principal_hash bytea,
    p_limit integer,
    p_cost integer
)
RETURNS TABLE (
    allowed boolean,
    remaining integer,
    retry_after_seconds bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_quota registry_notary_private.machine_quota%ROWTYPE;
BEGIN
    IF pg_catalog.octet_length(p_principal_hash) <> 32
       OR p_limit <= 0 OR p_cost <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid machine quota input';
    END IF;
    INSERT INTO registry_notary_private.machine_quota (
        principal_hash, window_started_at, window_expires_at, used
    ) VALUES (p_principal_hash, v_now, v_now + interval '1 minute', 0)
    ON CONFLICT (principal_hash) DO NOTHING;
    SELECT * INTO STRICT v_quota
      FROM registry_notary_private.machine_quota
     WHERE principal_hash = p_principal_hash
     FOR UPDATE;
    IF v_quota.window_expires_at <= v_now THEN
        UPDATE registry_notary_private.machine_quota
           SET window_started_at = v_now,
               window_expires_at = v_now + interval '1 minute',
               used = 0
         WHERE principal_hash = p_principal_hash;
        v_quota.window_expires_at := v_now + interval '1 minute';
        v_quota.used := 0;
    END IF;
    IF p_cost > p_limit - v_quota.used THEN
        RETURN QUERY SELECT FALSE, GREATEST(0, p_limit - v_quota.used),
            GREATEST(1::bigint, CEIL(EXTRACT(EPOCH FROM
                (v_quota.window_expires_at - v_now)))::bigint);
        RETURN;
    END IF;
    UPDATE registry_notary_private.machine_quota
       SET used = used + p_cost
     WHERE principal_hash = p_principal_hash;
    RETURN QUERY SELECT TRUE, p_limit - v_quota.used - p_cost, 0::bigint;
END
$function$;

CREATE FUNCTION registry_notary_api.subject_access_quota_debit_v1(
    p_bucket_kinds text[],
    p_key_hashes bytea[],
    p_limits integer[],
    p_window_seconds integer[]
)
RETURNS TABLE (
    allowed boolean,
    denied_bucket text,
    retry_after_seconds bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_size integer := pg_catalog.cardinality(p_bucket_kinds);
    v_index integer;
    v_other integer;
    v_quota registry_notary_private.subject_access_quota%ROWTYPE;
BEGIN
    IF v_size IS NULL OR v_size < 1 OR v_size > 8
       OR pg_catalog.array_ndims(p_bucket_kinds) <> 1
       OR pg_catalog.array_ndims(p_key_hashes) <> 1
       OR pg_catalog.array_ndims(p_limits) <> 1
       OR pg_catalog.array_ndims(p_window_seconds) <> 1
       OR pg_catalog.array_lower(p_bucket_kinds, 1) <> 1
       OR pg_catalog.array_lower(p_key_hashes, 1) <> 1
       OR pg_catalog.array_lower(p_limits, 1) <> 1
       OR pg_catalog.array_lower(p_window_seconds, 1) <> 1
       OR pg_catalog.cardinality(p_key_hashes) <> v_size
       OR pg_catalog.cardinality(p_limits) <> v_size
       OR pg_catalog.cardinality(p_window_seconds) <> v_size THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid quota group';
    END IF;
    FOR v_index IN 1..v_size LOOP
        IF p_bucket_kinds[v_index] IS NULL
           OR p_key_hashes[v_index] IS NULL
           OR p_limits[v_index] IS NULL
           OR p_window_seconds[v_index] IS NULL
           OR pg_catalog.octet_length(p_key_hashes[v_index]) <> 32
           OR p_limits[v_index] < 0
           OR p_window_seconds[v_index] NOT IN (60, 3600)
           OR p_bucket_kinds[v_index] NOT IN (
               'invalid_token_per_client_address',
               'per_principal',
               'subject_mismatch_per_principal',
               'per_holder_issuance',
               'credential_issuance_per_principal',
               'tx_code_attempt_per_code'
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid quota bucket';
        END IF;
        IF v_index > 1 THEN
            FOR v_other IN 1..(v_index - 1) LOOP
                IF p_bucket_kinds[v_other] = p_bucket_kinds[v_index]
                   AND p_key_hashes[v_other] = p_key_hashes[v_index] THEN
                    RAISE EXCEPTION USING ERRCODE = '22023',
                        MESSAGE = 'duplicate quota bucket';
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    -- Insert and lock in canonical order, independent of caller denial order.
    FOR v_index IN
        SELECT requested.ordinality::integer
          FROM pg_catalog.unnest(p_bucket_kinds) WITH ORDINALITY AS requested(bucket, ordinality)
         ORDER BY requested.bucket,
                  pg_catalog.encode(p_key_hashes[requested.ordinality::integer], 'hex')
    LOOP
        INSERT INTO registry_notary_private.subject_access_quota (
            bucket_kind, key_hash, window_started_at, window_expires_at, used
        ) VALUES (
            p_bucket_kinds[v_index], p_key_hashes[v_index], v_now,
            v_now + pg_catalog.make_interval(secs => p_window_seconds[v_index]), 0
        ) ON CONFLICT (bucket_kind, key_hash) DO NOTHING;
        SELECT * INTO STRICT v_quota
          FROM registry_notary_private.subject_access_quota
         WHERE bucket_kind = p_bucket_kinds[v_index]
           AND key_hash = p_key_hashes[v_index]
         FOR UPDATE;
        IF v_quota.window_expires_at <= v_now THEN
            UPDATE registry_notary_private.subject_access_quota
               SET window_started_at = v_now,
                   window_expires_at = v_now
                       + pg_catalog.make_interval(secs => p_window_seconds[v_index]),
                   used = 0
             WHERE bucket_kind = p_bucket_kinds[v_index]
               AND key_hash = p_key_hashes[v_index];
        END IF;
    END LOOP;

    -- Preserve caller order when selecting the denial bucket.
    FOR v_index IN 1..v_size LOOP
        SELECT * INTO STRICT v_quota
          FROM registry_notary_private.subject_access_quota
         WHERE bucket_kind = p_bucket_kinds[v_index]
           AND key_hash = p_key_hashes[v_index];
        IF p_limits[v_index] = 0 OR v_quota.used >= p_limits[v_index] THEN
            RETURN QUERY SELECT FALSE, p_bucket_kinds[v_index],
                GREATEST(1::bigint, CEIL(EXTRACT(EPOCH FROM
                    (v_quota.window_expires_at - v_now)))::bigint);
            RETURN;
        END IF;
    END LOOP;

    FOR v_index IN 1..v_size LOOP
        UPDATE registry_notary_private.subject_access_quota
           SET used = used + 1
         WHERE bucket_kind = p_bucket_kinds[v_index]
           AND key_hash = p_key_hashes[v_index];
    END LOOP;
    RETURN QUERY SELECT TRUE, NULL::text, 0::bigint;
END
$function$;

CREATE FUNCTION registry_notary_api.subject_access_quota_check_v1(
    p_bucket_kinds text[],
    p_key_hashes bytea[],
    p_limits integer[],
    p_window_seconds integer[]
)
RETURNS TABLE (
    allowed boolean,
    denied_bucket text,
    retry_after_seconds bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_size integer := pg_catalog.cardinality(p_bucket_kinds);
    v_index integer;
    v_other integer;
    v_quota registry_notary_private.subject_access_quota%ROWTYPE;
BEGIN
    IF v_size IS NULL OR v_size < 1 OR v_size > 8
       OR pg_catalog.array_ndims(p_bucket_kinds) <> 1
       OR pg_catalog.array_ndims(p_key_hashes) <> 1
       OR pg_catalog.array_ndims(p_limits) <> 1
       OR pg_catalog.array_ndims(p_window_seconds) <> 1
       OR pg_catalog.array_lower(p_bucket_kinds, 1) <> 1
       OR pg_catalog.array_lower(p_key_hashes, 1) <> 1
       OR pg_catalog.array_lower(p_limits, 1) <> 1
       OR pg_catalog.array_lower(p_window_seconds, 1) <> 1
       OR pg_catalog.cardinality(p_key_hashes) <> v_size
       OR pg_catalog.cardinality(p_limits) <> v_size
       OR pg_catalog.cardinality(p_window_seconds) <> v_size THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid quota group';
    END IF;
    FOR v_index IN 1..v_size LOOP
        IF p_bucket_kinds[v_index] IS NULL
           OR p_key_hashes[v_index] IS NULL
           OR p_limits[v_index] IS NULL
           OR p_window_seconds[v_index] IS NULL
           OR pg_catalog.octet_length(p_key_hashes[v_index]) <> 32
           OR p_limits[v_index] < 0
           OR p_window_seconds[v_index] NOT IN (60, 3600)
           OR p_bucket_kinds[v_index] NOT IN (
               'invalid_token_per_client_address',
               'per_principal',
               'subject_mismatch_per_principal',
               'per_holder_issuance',
               'credential_issuance_per_principal',
               'tx_code_attempt_per_code'
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid quota bucket';
        END IF;
        IF v_index > 1 THEN
            FOR v_other IN 1..(v_index - 1) LOOP
                IF p_bucket_kinds[v_other] = p_bucket_kinds[v_index]
                   AND p_key_hashes[v_other] = p_key_hashes[v_index] THEN
                    RAISE EXCEPTION USING ERRCODE = '22023',
                        MESSAGE = 'duplicate quota bucket';
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    -- This precheck deliberately does not insert, reset, lock, or debit rows.
    -- A later debit performs its own atomic decision against current state.
    FOR v_index IN 1..v_size LOOP
        IF p_limits[v_index] = 0 THEN
            RETURN QUERY SELECT FALSE, p_bucket_kinds[v_index],
                p_window_seconds[v_index]::bigint;
            RETURN;
        END IF;
        SELECT * INTO v_quota
          FROM registry_notary_private.subject_access_quota
         WHERE bucket_kind = p_bucket_kinds[v_index]
           AND key_hash = p_key_hashes[v_index];
        IF FOUND
           AND v_quota.window_expires_at > v_now
           AND v_quota.used >= p_limits[v_index] THEN
            RETURN QUERY SELECT FALSE, p_bucket_kinds[v_index],
                GREATEST(1::bigint, CEIL(EXTRACT(EPOCH FROM
                    (v_quota.window_expires_at - v_now)))::bigint);
            RETURN;
        END IF;
    END LOOP;
    RETURN QUERY SELECT TRUE, NULL::text, 0::bigint;
END
$function$;

CREATE FUNCTION registry_notary_api.preauthorization_login_reserve_v1(
    p_state_hash bytea,
    p_credential_configuration_id text,
    p_key_id bytea,
    p_aead_nonce bytea,
    p_ciphertext bytea,
    p_expires_at timestamptz
)
RETURNS smallint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
BEGIN
    IF p_expires_at <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid login state expiry';
    END IF;
    -- The table lock serializes the exact 4,096-row capacity decision across
    -- replicas. It is bounded because this table cannot exceed that capacity.
    LOCK TABLE registry_notary_private.preauthorization_login_state
        IN SHARE ROW EXCLUSIVE MODE;
    DELETE FROM registry_notary_private.preauthorization_login_state
     WHERE expires_at <= v_now;
    IF EXISTS (
        SELECT 1 FROM registry_notary_private.preauthorization_login_state
         WHERE state_hash = p_state_hash
    ) THEN
        RETURN 0;
    END IF;
    SELECT pg_catalog.count(*) INTO v_count
      FROM registry_notary_private.preauthorization_login_state;
    IF v_count >= 4096 THEN
        RETURN -1;
    END IF;
    INSERT INTO registry_notary_private.preauthorization_login_state (
        state_hash, credential_configuration_id, key_id, aead_nonce,
        ciphertext, created_at, expires_at
    ) VALUES (
        p_state_hash, p_credential_configuration_id, p_key_id, p_aead_nonce,
        p_ciphertext, v_now, p_expires_at
    );
    RETURN 1;
END
$function$;

CREATE FUNCTION registry_notary_api.preauthorization_login_consume_v1(
    p_state_hash bytea
)
RETURNS TABLE (
    credential_configuration_id text,
    key_id bytea,
    aead_nonce bytea,
    ciphertext bytea,
    expires_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    DELETE FROM registry_notary_private.preauthorization_login_state AS stored
     WHERE stored.state_hash = p_state_hash
       AND stored.expires_at > pg_catalog.clock_timestamp()
    RETURNING stored.credential_configuration_id,
              stored.key_id,
              stored.aead_nonce,
              stored.ciphertext,
              stored.expires_at
$function$;

CREATE FUNCTION registry_notary_api.preauthorization_tx_code_reserve_v1(
    p_jti_hash bytea,
    p_key_id bytea,
    p_pin_verifier bytea,
    p_pin_length smallint,
    p_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
BEGIN
    IF p_expires_at <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid transaction code expiry';
    END IF;
    DELETE FROM registry_notary_private.preauthorization_tx_code
     WHERE jti_hash = p_jti_hash AND expires_at <= v_now;
    INSERT INTO registry_notary_private.preauthorization_tx_code (
        jti_hash, key_id, pin_verifier, pin_length, created_at, expires_at
    ) VALUES (
        p_jti_hash, p_key_id, p_pin_verifier, p_pin_length, v_now, p_expires_at
    ) ON CONFLICT (jti_hash) DO NOTHING;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count = 1;
END
$function$;

CREATE FUNCTION registry_notary_api.preauthorization_tx_code_peek_v1(
    p_jti_hash bytea
)
RETURNS TABLE (
    key_id bytea,
    pin_verifier bytea,
    pin_length smallint,
    expires_at timestamptz
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT stored.key_id,
           stored.pin_verifier,
           stored.pin_length,
           stored.expires_at
      FROM registry_notary_private.preauthorization_tx_code AS stored
     WHERE stored.jti_hash = p_jti_hash
       AND stored.expires_at > pg_catalog.clock_timestamp()
$function$;

CREATE FUNCTION registry_notary_api.preauthorization_redeem_v1(
    p_replay_scope_hash bytea,
    p_jti_hash bytea,
    p_code_expires_at timestamptz,
    p_pin_required boolean,
    p_expected_pin_verifier bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
    v_tx_code registry_notary_private.preauthorization_tx_code%ROWTYPE;
BEGIN
    IF pg_catalog.octet_length(p_replay_scope_hash) <> 32
       OR pg_catalog.octet_length(p_jti_hash) <> 32
       OR p_code_expires_at <= v_now
       OR (p_pin_required AND pg_catalog.octet_length(p_expected_pin_verifier) <> 32)
       OR (NOT p_pin_required AND p_expected_pin_verifier IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid redemption input';
    END IF;
    IF p_pin_required THEN
        SELECT * INTO v_tx_code
          FROM registry_notary_private.preauthorization_tx_code
         WHERE jti_hash = p_jti_hash
         FOR UPDATE;
        IF NOT FOUND
           OR v_tx_code.expires_at <= v_now
           OR v_tx_code.pin_verifier <> p_expected_pin_verifier THEN
            RETURN FALSE;
        END IF;
    END IF;

    INSERT INTO registry_notary_private.replay_identifier (
        scope_hash, identifier_hash, created_at, expires_at
    ) VALUES (p_replay_scope_hash, p_jti_hash, v_now, p_code_expires_at)
    ON CONFLICT (scope_hash, identifier_hash) DO UPDATE
       SET created_at = EXCLUDED.created_at,
           expires_at = EXCLUDED.expires_at
     WHERE registry_notary_private.replay_identifier.expires_at <= v_now;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    IF v_count <> 1 THEN
        RETURN FALSE;
    END IF;
    IF p_pin_required THEN
        DELETE FROM registry_notary_private.preauthorization_tx_code
         WHERE jti_hash = p_jti_hash;
    END IF;
    RETURN TRUE;
END
$function$;

CREATE FUNCTION registry_notary_api.retention_prune_v1(p_batch_size integer)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_count bigint;
    v_total bigint := 0;
BEGIN
    IF p_batch_size NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid retention batch';
    END IF;

    WITH candidates AS (
        SELECT scope_hash, identifier_hash
          FROM registry_notary_private.replay_identifier
         WHERE expires_at <= v_now
         ORDER BY expires_at, scope_hash, identifier_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.replay_identifier AS stored
         USING candidates
         WHERE stored.scope_hash = candidates.scope_hash
           AND stored.identifier_hash = candidates.identifier_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;

    WITH candidates AS (
        SELECT scope_hash, nonce_hash
          FROM registry_notary_private.consumable_nonce
         WHERE (state = 'reserved' AND reservation_expires_at <= v_now)
            OR (state = 'consumed' AND tombstone_expires_at <= v_now)
         ORDER BY updated_at, scope_hash, nonce_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.consumable_nonce AS stored
         USING candidates
         WHERE stored.scope_hash = candidates.scope_hash
           AND stored.nonce_hash = candidates.nonce_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;

    WITH candidates AS (
        SELECT evaluation_id FROM registry_notary_private.evaluation
         WHERE expires_at <= v_now
         ORDER BY expires_at, evaluation_id
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.evaluation AS stored
         USING candidates WHERE stored.evaluation_id = candidates.evaluation_id
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;

    WITH candidates AS (
        SELECT key_hash FROM registry_notary_private.batch_idempotency
         WHERE retention_expires_at <= v_now
         ORDER BY retention_expires_at, key_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.batch_idempotency AS stored
         USING candidates WHERE stored.key_hash = candidates.key_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;

    WITH candidates AS (
        SELECT credential_id FROM registry_notary_private.credential_status
         WHERE purge_after <= v_now
         ORDER BY purge_after, credential_id
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.credential_status AS stored
         USING candidates WHERE stored.credential_id = candidates.credential_id
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;

    WITH candidates AS (
        SELECT principal_hash FROM registry_notary_private.machine_quota
         WHERE window_expires_at <= v_now
         ORDER BY window_expires_at, principal_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.machine_quota AS stored
         USING candidates WHERE stored.principal_hash = candidates.principal_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;

    WITH candidates AS (
        SELECT bucket_kind, key_hash
          FROM registry_notary_private.subject_access_quota
         WHERE window_expires_at <= v_now
         ORDER BY window_expires_at, bucket_kind, key_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.subject_access_quota AS stored
         USING candidates
         WHERE stored.bucket_kind = candidates.bucket_kind
           AND stored.key_hash = candidates.key_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;

    WITH candidates AS (
        SELECT state_hash FROM registry_notary_private.preauthorization_login_state
         WHERE expires_at <= v_now
         ORDER BY expires_at, state_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.preauthorization_login_state AS stored
         USING candidates WHERE stored.state_hash = candidates.state_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;

    WITH candidates AS (
        SELECT jti_hash FROM registry_notary_private.preauthorization_tx_code
         WHERE expires_at <= v_now
         ORDER BY expires_at, jti_hash
         LIMIT p_batch_size FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM registry_notary_private.preauthorization_tx_code AS stored
         USING candidates WHERE stored.jti_hash = candidates.jti_hash
        RETURNING 1
    ) SELECT pg_catalog.count(*) INTO v_count FROM deleted;
    v_total := v_total + v_count;

    RETURN v_total;
END
$function$;

REVOKE ALL ON ALL TABLES IN SCHEMA registry_notary_private FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA registry_notary_private FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA registry_notary_api FROM PUBLIC;
"#;

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc, time::Duration};

    use crate::state_plane::{
        NotaryPostgresStatePlaneError, NotaryPostgresStatePlaneReadiness,
        NotaryPostgresStatePlaneRuntime, PostgresStatePlaneConfig,
    };

    use super::*;

    const DATABASE_URL_ENV: &str = "REGISTRY_NOTARY_STATE_POSTGRES_TEST_URL";
    const DATABASE_CA_ENV: &str = "REGISTRY_NOTARY_STATE_POSTGRES_TEST_CA";
    const POOL_DATABASE_URL_ENV: &str = "REGISTRY_NOTARY_STATE_POOL_TEST_URL";
    const OWNER_ROLE: &str = "registry_notary_owner_test";
    const RUNTIME_ROLE: &str = "registry_notary_runtime_test";
    const MIGRATION_ROLE: &str = "registry_notary_migration_test";
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
            "nonce=keyed-reserve-consume-sixty-second-tombstone-v1",
            "evaluation=client-bound-stored-record-v2-atomic-publication-expiry-v1",
            "batch=keyed-request-owner-lease-quota-once-takeover-atomic-completion-stored-response-v2-fifteen-minute-retention-v1",
            "credential-status=insert-only-locked-transition-terminal-revocation-expiry-retention-monotonic-updated-at-v1",
            "machine-quota=keyed-principal-fixed-minute-whole-cost-atomic-v1",
            "subject-access-quota=keyed-pseudonym-six-closed-buckets-fixed-windows-canonical-lock-order-caller-denial-order-atomic-all-or-none-check-only-no-mutation-v1",
            "preauthorization-login=keyed-state-capacity-4096-encrypted-single-consume-expiry-v1",
            "preauthorization-tx-code=keyed-jti-keyed-pin-verifier-peek-redeem-with-replay-one-winner-expiry-v1",
            "retention=bounded-expiry-prune-skip-locked-v1",
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
        assert!(acl
            .contains("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA registry_notary_api FROM PUBLIC"));
        for table in [
            "replay_identifier",
            "consumable_nonce",
            "evaluation",
            "batch_idempotency",
            "credential_status",
            "machine_quota",
            "subject_access_quota",
            "preauthorization_login_state",
            "preauthorization_tx_code",
        ] {
            assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains(table));
        }
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
                   WHERE rolname IN ($1, $2, $3))",
                &[&OWNER_ROLE, &RUNTIME_ROLE, &MIGRATION_ROLE],
            )
            .await?
            .get(0);
        if occupied {
            return Err("the dedicated conformance database is not empty".into());
        }
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
                SELF_ATTESTATION_QUOTA_CHECK_SQL,
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
                SELF_ATTESTATION_QUOTA_CHECK_SQL,
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
                SELF_ATTESTATION_QUOTA_DEBIT_SQL,
                &concurrent_buckets,
                &concurrent_hashes,
                &concurrent_limits,
                &concurrent_windows,
            ),
            subject_access_quota_decision(
                &runtime_peer,
                SELF_ATTESTATION_QUOTA_DEBIT_SQL,
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
                SELF_ATTESTATION_QUOTA_DEBIT_SQL,
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
                SELF_ATTESTATION_QUOTA_DEBIT_SQL,
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
                SELF_ATTESTATION_QUOTA_CHECK_SQL,
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
                SELF_ATTESTATION_QUOTA_DEBIT_SQL,
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
                SELF_ATTESTATION_QUOTA_DEBIT_SQL,
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
        assert_credential_status_and_machine_quota_contracts(&database_url, &runtime, &admin)
            .await?;
        assert_preauthorization_contracts(&database_url, &runtime, &admin).await?;
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
            Duration::from_secs(2),
            Duration::from_millis(100),
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
            waited >= Duration::from_millis(50) && waited < Duration::from_secs(1),
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

    const SELF_ATTESTATION_QUOTA_CHECK_SQL: &str = "SELECT allowed, denied_bucket FROM \
         registry_notary_api.subject_access_quota_check_v1($1, $2, $3, $4)";
    const SELF_ATTESTATION_QUOTA_DEBIT_SQL: &str = "SELECT allowed, denied_bucket FROM \
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
        let (peer, peer_driver) = connect_as(database_url, RUNTIME_ROLE).await?;
        let (left, right) = tokio::join!(
            async {
                runtime
                    .query_one(
                        "SELECT registry_notary_api.nonce_consume_v1($1, $2)",
                        &[&nonce_scope, &nonce],
                    )
                    .await
            },
            async {
                peer.query_one(
                    "SELECT registry_notary_api.nonce_consume_v1($1, $2)",
                    &[&nonce_scope, &nonce],
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
                "SELECT registry_notary_api.nonce_consume_v1($1, $2)",
                &[&nonce_scope, &nonce],
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
        assert!(runtime
            .query_opt(
                "SELECT * FROM registry_notary_api.credential_status_get_v1('credential-expired')",
                &[],
            )
            .await?
            .is_some());
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
        let expires_at = time::OffsetDateTime::now_utc() + time::Duration::minutes(5);
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
        drop(peer);
        peer_driver.abort();
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
                          registry_notary_private.subject_access_quota,
                          registry_notary_private.preauthorization_login_state,
                          registry_notary_private.preauthorization_tx_code;
                 INSERT INTO registry_notary_private.replay_identifier
                    (scope_hash, identifier_hash, created_at, expires_at)
                 SELECT decode(repeat('90', 32), 'hex'), decode(repeat(marker, 32), 'hex'),
                        clock_timestamp() - interval '2 seconds',
                        clock_timestamp() + lifetime
                   FROM (VALUES ('91', interval '-1 second'),
                                ('92', interval '5 minutes')) AS rows(marker, lifetime);
                 INSERT INTO registry_notary_private.consumable_nonce
                    (scope_hash, nonce_hash, state, reservation_expires_at,
                     tombstone_expires_at, created_at, updated_at)
                 SELECT decode(repeat('93', 32), 'hex'), decode(repeat(marker, 32), 'hex'),
                        'reserved', clock_timestamp() + lifetime, NULL,
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
                                ('a9', interval '5 minutes')) AS rows(marker, lifetime);",
            )
            .await?;
        let pruned: i64 = runtime
            .query_one("SELECT registry_notary_api.retention_prune_v1(1000)", &[])
            .await?
            .get(0);
        assert_eq!(
            pruned, 9,
            "each typed state table must prune its expired row"
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
                    (SELECT count(*) FROM registry_notary_private.subject_access_quota) +
                    (SELECT count(*) FROM registry_notary_private.preauthorization_login_state) +
                    (SELECT count(*) FROM registry_notary_private.preauthorization_tx_code)",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(remaining, 9, "retention must preserve every live row");
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
}
