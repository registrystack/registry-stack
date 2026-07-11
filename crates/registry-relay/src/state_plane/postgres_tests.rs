// SPDX-License-Identifier: Apache-2.0
//! Disposable PostgreSQL conformance coverage for Relay's audit state plane.
//!
//! Run only against a dedicated disposable database:
//!
//! `REGISTRY_RELAY_STATE_PLANE_POSTGRES_TEST_URL='postgres://...' cargo test \
//!   -p registry-relay --lib postgres_state_plane -- --ignored --nocapture`

use std::{collections::HashMap, env, fs, sync::Arc, time::Duration};

use postgres_native_tls::MakeTlsConnector;
use registry_platform_audit::{
    verify_chain, AuditChainHasher, AuditEnvelope, ChainVerificationError, DurableAuditOperationId,
    DurableAuditPhase, DurableAuditSink, DurableAuditStreamKind, DurableAuditWrite,
    DurableAuditWriteError, DurableAuditWriteOutcome,
};
use serde_json::json;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_postgres::{error::SqlState, Client, Config, GenericClient};
use ulid::Ulid;

use super::migration::RUNTIME_SESSION_LIMITS_SQL;
use super::{
    install_postgres_state_plane_v1, AuditChainKeyEpochId, CompletionAttemptReference,
    PostgresDurableAuditStatePlane, RuntimeDatabaseRole, StatePlaneInitializationError,
    StatePlaneInstallError, StatePlaneReadiness, DURABLE_AUDIT_CAPABILITY_V1,
    POSTGRES_STATE_PLANE_MIGRATION_V1, STATE_PLANE_SCHEMA_FINGERPRINT_V1,
};

const DATABASE_URL_ENV: &str = "REGISTRY_RELAY_STATE_PLANE_POSTGRES_TEST_URL";
const PREPARED_DATABASE_URL_ENV: &str = "REGISTRY_RELAY_STATE_PLANE_PREPARED_POSTGRES_TEST_URL";
const UNSAFE_DURABILITY_DATABASE_URL_ENV: &str =
    "REGISTRY_RELAY_STATE_PLANE_UNSAFE_DURABILITY_POSTGRES_TEST_URL";
const TEST_ADVISORY_LOCK: i64 = 7_221_091_441;
const SNAPSHOT_SQL: &str = "SELECT * FROM relay_state_api.audit_phase_snapshot_v1($1, $2, $3, $4)";
const CAS_SQL: &str = "SELECT * FROM relay_state_api.audit_phase_cas_v1(\
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13\
)";

#[derive(Debug)]
struct DirectCandidate {
    predecessor: Option<[u8; 32]>,
    generation: i64,
}

async fn postgres_client(
    url: &str,
) -> Result<(Client, JoinHandle<Result<(), tokio_postgres::Error>>), Box<dyn std::error::Error>> {
    postgres_client_config(url.parse()?).await
}

async fn postgres_client_as(
    url: &str,
    user: &str,
    password: &str,
) -> Result<(Client, JoinHandle<Result<(), tokio_postgres::Error>>), Box<dyn std::error::Error>> {
    let mut config: Config = url.parse()?;
    config.user(user).password(password);
    postgres_client_config(config).await
}

async fn postgres_client_config(
    config: Config,
) -> Result<(Client, JoinHandle<Result<(), tokio_postgres::Error>>), Box<dyn std::error::Error>> {
    let mut builder = native_tls::TlsConnector::builder();
    if let Ok(path) = env::var("REGISTRY_RELAY_STATE_PLANE_POSTGRES_ROOT_CERT_PATH") {
        let pem = fs::read(path)?;
        builder.add_root_certificate(native_tls::Certificate::from_pem(&pem)?);
    }
    let connector = MakeTlsConnector::new(builder.build()?);
    let (client, connection) = config.connect(connector).await?;
    let driver = tokio::spawn(connection);
    Ok((client, driver))
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn role_name(kind: &str) -> String {
    format!(
        "relay_sp_{kind}_{}",
        Ulid::new().to_string().to_ascii_lowercase()
    )
}

fn attempt_write(operation_id: &DurableAuditOperationId, marker: &str) -> DurableAuditWrite {
    DurableAuditWrite::new(
        DurableAuditStreamKind::Consultation,
        operation_id.clone(),
        DurableAuditPhase::Attempt,
        json!({
            "authorization": "accepted",
            "test_marker": marker,
        }),
    )
    .expect("test attempt is valid")
}

async fn direct_snapshot(
    client: &(impl GenericClient + Sync),
    write: &DurableAuditWrite,
) -> Result<DirectCandidate, Box<dyn std::error::Error>> {
    let row = client
        .query_one(
            SNAPSHOT_SQL,
            &[
                &write.key().stream_kind().as_str(),
                &write.key().operation_id().as_str(),
                &write.key().phase().as_str(),
                &write.payload_digest().as_bytes().as_slice(),
            ],
        )
        .await?;
    assert_eq!(row.try_get::<_, &str>("outcome")?, "candidate");
    let predecessor = row
        .try_get::<_, Option<Vec<u8>>>("candidate_predecessor_hash")?
        .map(|bytes| bytes.as_slice().try_into())
        .transpose()?;
    Ok(DirectCandidate {
        predecessor,
        generation: row.try_get("candidate_generation")?,
    })
}

async fn direct_cas(
    client: &(impl GenericClient + Sync),
    write: &DurableAuditWrite,
    candidate: &DirectCandidate,
    envelope: &AuditEnvelope,
) -> Result<String, Box<dyn std::error::Error>> {
    let record_json = serde_json::to_string(&envelope.record)?;
    let envelope_json = serde_json::to_string(envelope)?;
    let predecessor = candidate.predecessor.as_ref().map(<[u8; 32]>::as_slice);
    let no_attempt_envelope: Option<&str> = None;
    let no_attempt_hash: Option<&[u8]> = None;
    let row = client
        .query_one(
            CAS_SQL,
            &[
                &write.key().stream_kind().as_str(),
                &write.key().operation_id().as_str(),
                &write.key().phase().as_str(),
                &write.payload_digest().as_bytes().as_slice(),
                &candidate.generation,
                &predecessor,
                &envelope.envelope_id,
                &envelope.timestamp_unix_ms,
                &record_json,
                &envelope_json,
                &envelope.record_hash.as_slice(),
                &no_attempt_envelope,
                &no_attempt_hash,
            ],
        )
        .await?;
    Ok(row.try_get("outcome")?)
}

async fn set_role(client: &Client, role: &str) -> Result<(), tokio_postgres::Error> {
    client
        .batch_execute(&format!("SET ROLE {}", quote_identifier(role)))
        .await
}

async fn reset_role(client: &Client) -> Result<(), tokio_postgres::Error> {
    client.batch_execute("RESET ROLE").await
}

async fn seed_catalog_for_unsafe_restart(
    client: &Client,
    runtime_role_name: &str,
    chain_key_epoch_id: &AuditChainKeyEpochId,
) -> Result<(), Box<dyn std::error::Error>> {
    client
        .batch_execute(POSTGRES_STATE_PLANE_MIGRATION_V1)
        .await?;
    client
        .execute(
            "INSERT INTO relay_state_private.state_plane_metadata ( \
                 singleton, schema_version, capability_id, capability_fingerprint, \
                 owner_role_oid, runtime_role_oid, chain_key_epoch_id \
             ) SELECT true, 1, $1, $2, owner_role.oid, runtime_role.oid, $3 \
             FROM pg_catalog.pg_roles AS owner_role \
             JOIN pg_catalog.pg_roles AS runtime_role ON runtime_role.rolname = $4 \
             WHERE owner_role.rolname = current_user",
            &[
                &DURABLE_AUDIT_CAPABILITY_V1,
                &STATE_PLANE_SCHEMA_FINGERPRINT_V1,
                &chain_key_epoch_id.as_str(),
                &runtime_role_name,
            ],
        )
        .await?;
    client
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA relay_state_api TO {runtime}; \
             GRANT EXECUTE ON FUNCTION \
                 relay_state_api.audit_phase_snapshot_v1(text, text, text, bytea) \
                 TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.audit_phase_cas_v1( \
                 text, text, text, bytea, bigint, bytea, text, bigint, \
                 text, text, bytea, text, bytea \
             ) TO {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.audit_readiness_v1(text) \
                 TO {runtime};",
            runtime = quote_identifier(runtime_role_name),
        ))
        .await?;
    Ok(())
}

fn order_chain(mut envelopes: Vec<AuditEnvelope>) -> Vec<AuditEnvelope> {
    let expected_len = envelopes.len();
    let mut by_predecessor: HashMap<Option<[u8; 32]>, AuditEnvelope> = envelopes
        .drain(..)
        .map(|envelope| (envelope.prev_hash, envelope))
        .collect();
    assert_eq!(
        by_predecessor.len(),
        expected_len,
        "stored chain must not fork"
    );
    let mut ordered = Vec::with_capacity(by_predecessor.len());
    let mut predecessor = None;
    while let Some(envelope) = by_predecessor.remove(&predecessor) {
        predecessor = Some(envelope.record_hash);
        ordered.push(envelope);
    }
    assert!(by_predecessor.is_empty(), "stored chain must be linear");
    ordered
}

#[tokio::test]
#[ignore = "requires dedicated REGISTRY_RELAY_STATE_PLANE_POSTGRES_TEST_URL"]
async fn postgres_state_plane_enforces_role_catalog_and_chain_contract(
) -> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = env::var(DATABASE_URL_ENV) else {
        eprintln!("SKIPPED: {DATABASE_URL_ENV} is not set");
        return Ok(());
    };

    let (mut admin, admin_driver) = postgres_client(&database_url).await?;
    admin
        .execute("SELECT pg_advisory_lock($1)", &[&TEST_ADVISORY_LOCK])
        .await?;
    admin
        .batch_execute(
            "DROP SCHEMA IF EXISTS relay_state_api CASCADE; \
             DROP SCHEMA IF EXISTS relay_state_private CASCADE;",
        )
        .await?;

    let owner_role = role_name("owner");
    let stale_owner_role = role_name("stale");
    let runtime_role_name = role_name("runtime");
    let private_reader_role = role_name("reader");
    let attacker_role = role_name("attacker");
    let bridge_role = role_name("bridge");
    let runtime_password = Ulid::new().to_string();
    let attacker_password = Ulid::new().to_string();
    let database_name: String = admin
        .query_one("SELECT current_database()", &[])
        .await?
        .get(0);
    admin
        .batch_execute(&format!(
            r#"
CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE {stale} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE {runtime} LOGIN PASSWORD '{runtime_password}' NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE {reader} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE {attacker} LOGIN PASSWORD '{attacker_password}' NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
CREATE ROLE {bridge} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;
GRANT CREATE ON DATABASE {database} TO {owner};
GRANT CREATE ON DATABASE {database} TO {stale};
"#,
            owner = quote_identifier(&owner_role),
            stale = quote_identifier(&stale_owner_role),
            runtime = quote_identifier(&runtime_role_name),
            reader = quote_identifier(&private_reader_role),
            attacker = quote_identifier(&attacker_role),
            bridge = quote_identifier(&bridge_role),
            database = quote_identifier(&database_name),
        ))
        .await?;

    let runtime_role = RuntimeDatabaseRole::parse(&runtime_role_name)?;
    let chain_key_epoch_id = AuditChainKeyEpochId::parse("test-chain-key-epoch-1")?;

    let server = admin
        .query_one(
            "SELECT current_setting('server_version_num')::integer / 10000 AS major, \
                    current_setting('max_prepared_transactions')::integer AS prepared, \
                    NOT pg_catalog.pg_is_in_recovery() AS primary_writable",
            &[],
        )
        .await?;
    let server_major: i32 = server.try_get("major")?;
    assert!(
        (16..=18).contains(&server_major),
        "test requires an explicitly supported PostgreSQL major"
    );
    assert_eq!(server.try_get::<_, i32>("prepared")?, 0);
    assert!(server.try_get::<_, bool>("primary_writable")?);

    // Both directions around both bound roles are forbidden. NOINHERIT does
    // not prevent SET ROLE, and an endpoint edge is necessarily present for
    // every transitive path.
    admin
        .batch_execute(&format!(
            "GRANT {owner} TO {attacker} WITH INHERIT FALSE, SET TRUE;",
            owner = quote_identifier(&owner_role),
            attacker = quote_identifier(&attacker_role),
        ))
        .await?;
    let (mut non_superuser_admin, non_superuser_admin_driver) =
        postgres_client_as(&database_url, &attacker_role, &attacker_password).await?;
    set_role(&non_superuser_admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(
            &mut non_superuser_admin,
            &runtime_role,
            &chain_key_epoch_id,
        )
        .await,
        Err(StatePlaneInstallError::InvalidMigrationAuthority)
    );
    reset_role(&non_superuser_admin).await?;
    drop(non_superuser_admin);
    non_superuser_admin_driver.abort();
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(&mut admin, &runtime_role, &chain_key_epoch_id).await,
        Err(StatePlaneInstallError::OwnerRoleNotIsolated)
    );
    reset_role(&admin).await?;
    admin
        .batch_execute(&format!(
            "REVOKE {owner} FROM {attacker};",
            owner = quote_identifier(&owner_role),
            attacker = quote_identifier(&attacker_role),
        ))
        .await?;

    admin
        .batch_execute(&format!(
            "GRANT {owner} TO {bridge} WITH INHERIT FALSE, SET TRUE; \
             GRANT {bridge} TO {attacker} WITH INHERIT FALSE, SET TRUE;",
            owner = quote_identifier(&owner_role),
            bridge = quote_identifier(&bridge_role),
            attacker = quote_identifier(&attacker_role),
        ))
        .await?;
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(&mut admin, &runtime_role, &chain_key_epoch_id).await,
        Err(StatePlaneInstallError::OwnerRoleNotIsolated)
    );
    reset_role(&admin).await?;
    admin
        .batch_execute(&format!(
            "REVOKE {bridge} FROM {attacker}; REVOKE {owner} FROM {bridge};",
            owner = quote_identifier(&owner_role),
            bridge = quote_identifier(&bridge_role),
            attacker = quote_identifier(&attacker_role),
        ))
        .await?;

    admin
        .batch_execute(&format!(
            "GRANT {bridge} TO {owner} WITH INHERIT FALSE, SET TRUE;",
            owner = quote_identifier(&owner_role),
            bridge = quote_identifier(&bridge_role),
        ))
        .await?;
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(&mut admin, &runtime_role, &chain_key_epoch_id).await,
        Err(StatePlaneInstallError::OwnerRoleNotIsolated)
    );
    reset_role(&admin).await?;
    admin
        .batch_execute(&format!(
            "REVOKE {bridge} FROM {owner};",
            owner = quote_identifier(&owner_role),
            bridge = quote_identifier(&bridge_role),
        ))
        .await?;

    for (grant, revoke) in [
        (
            format!(
                "GRANT {runtime} TO {attacker} WITH INHERIT FALSE, SET TRUE;",
                runtime = quote_identifier(&runtime_role_name),
                attacker = quote_identifier(&attacker_role),
            ),
            format!(
                "REVOKE {runtime} FROM {attacker};",
                runtime = quote_identifier(&runtime_role_name),
                attacker = quote_identifier(&attacker_role),
            ),
        ),
        (
            format!(
                "GRANT {bridge} TO {runtime} WITH INHERIT FALSE, SET TRUE;",
                runtime = quote_identifier(&runtime_role_name),
                bridge = quote_identifier(&bridge_role),
            ),
            format!(
                "REVOKE {bridge} FROM {runtime};",
                runtime = quote_identifier(&runtime_role_name),
                bridge = quote_identifier(&bridge_role),
            ),
        ),
    ] {
        admin.batch_execute(&grant).await?;
        set_role(&admin, &owner_role).await?;
        assert_eq!(
            install_postgres_state_plane_v1(&mut admin, &runtime_role, &chain_key_epoch_id).await,
            Err(StatePlaneInstallError::RuntimeRoleNotIsolated)
        );
        reset_role(&admin).await?;
        admin.batch_execute(&revoke).await?;
    }

    // A partial installation owned by anybody else is never silently adopted.
    set_role(&admin, &stale_owner_role).await?;
    admin
        .batch_execute("CREATE SCHEMA relay_state_private; CREATE SCHEMA relay_state_api;")
        .await?;
    reset_role(&admin).await?;
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(&mut admin, &runtime_role, &chain_key_epoch_id).await,
        Err(StatePlaneInstallError::CapabilityDrift)
    );
    reset_role(&admin).await?;
    admin
        .batch_execute(
            "DROP SCHEMA relay_state_api CASCADE; DROP SCHEMA relay_state_private CASCADE;",
        )
        .await?;

    // Independent clean installers converge through the fixed transaction
    // advisory lock. The second then observes an exactly attested installation.
    let (mut concurrent_admin, concurrent_admin_driver) = postgres_client(&database_url).await?;
    set_role(&admin, &owner_role).await?;
    set_role(&concurrent_admin, &owner_role).await?;
    let (first_install, second_install) = tokio::join!(
        install_postgres_state_plane_v1(&mut admin, &runtime_role, &chain_key_epoch_id),
        install_postgres_state_plane_v1(&mut concurrent_admin, &runtime_role, &chain_key_epoch_id)
    );
    assert_eq!(first_install, Ok(()));
    assert_eq!(second_install, Ok(()));
    reset_role(&admin).await?;
    reset_role(&concurrent_admin).await?;
    drop(concurrent_admin);
    concurrent_admin_driver.abort();
    let _ = concurrent_admin_driver.await;

    set_role(&admin, &owner_role).await?;
    install_postgres_state_plane_v1(&mut admin, &runtime_role, &chain_key_epoch_id).await?;
    reset_role(&admin).await?;

    let metadata = admin
        .query_one(
            r#"
SELECT metadata.owner_role_oid::bigint, metadata.runtime_role_oid::bigint,
       metadata.capability_fingerprint, metadata.chain_key_epoch_id,
       owner_role.rolcanlogin, runtime_role.rolcanlogin
FROM relay_state_private.state_plane_metadata AS metadata
JOIN pg_roles AS owner_role ON owner_role.oid = metadata.owner_role_oid
JOIN pg_roles AS runtime_role ON runtime_role.oid = metadata.runtime_role_oid
WHERE metadata.singleton = true
"#,
            &[],
        )
        .await?;
    assert_ne!(metadata.get::<_, i64>(0), metadata.get::<_, i64>(1));
    assert_eq!(
        metadata.get::<_, &str>(2),
        STATE_PLANE_SCHEMA_FINGERPRINT_V1
    );
    assert_eq!(metadata.get::<_, &str>(3), chain_key_epoch_id.as_str());
    assert!(!metadata.get::<_, bool>(4));
    assert!(metadata.get::<_, bool>(5));

    let (unkeyed_client, unkeyed_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    assert_eq!(
        PostgresDurableAuditStatePlane::connect(
            unkeyed_client,
            AuditChainHasher::unkeyed_dev_only(),
            chain_key_epoch_id.clone(),
        )
        .await
        .err()
        .expect("unkeyed production construction must fail"),
        StatePlaneInitializationError::UnkeyedAuditChain
    );
    unkeyed_driver.abort();

    let secret_env = format!(
        "REGISTRY_RELAY_STATE_PLANE_TEST_SECRET_{}",
        Ulid::new().to_string()
    );
    env::set_var(
        &secret_env,
        "test-only-state-plane-chain-secret-at-least-thirty-two-bytes",
    );
    let test_chain_hasher = AuditChainHasher::from_env(&secret_env)?;
    env::remove_var(&secret_env);

    // SUSET role/database defaults are inherited before Relay receives the
    // Client. The runtime cannot repair session_replication_role, and replica
    // mode disables the origin FK triggers, so both inheritance paths must be
    // rejected on a fresh login.
    for (set_replica, reset_replica) in [
        (
            format!(
                "ALTER ROLE {} SET session_replication_role = 'replica'",
                quote_identifier(&runtime_role_name)
            ),
            format!(
                "ALTER ROLE {} RESET session_replication_role",
                quote_identifier(&runtime_role_name)
            ),
        ),
        (
            format!(
                "ALTER DATABASE {} SET session_replication_role = 'replica'",
                quote_identifier(&database_name)
            ),
            format!(
                "ALTER DATABASE {} RESET session_replication_role",
                quote_identifier(&database_name)
            ),
        ),
    ] {
        admin.batch_execute(&set_replica).await?;
        let (replica_client, replica_driver) =
            postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
        let inherited_mode: String = replica_client
            .query_one("SHOW session_replication_role", &[])
            .await?
            .try_get(0)?;
        let replica_ready: bool = replica_client
            .query_one(
                "SELECT ready FROM relay_state_api.audit_readiness_v1($1)",
                &[&chain_key_epoch_id.as_str()],
            )
            .await?
            .try_get("ready")?;
        let replica_connect = PostgresDurableAuditStatePlane::connect(
            replica_client,
            test_chain_hasher.clone(),
            chain_key_epoch_id.clone(),
        )
        .await;
        replica_driver.abort();
        admin.batch_execute(&reset_replica).await?;
        assert_eq!(inherited_mode, "replica");
        assert!(!replica_ready);
        assert_eq!(
            replica_connect
                .err()
                .expect("replica-mode runtime must fail attestation"),
            StatePlaneInitializationError::CapabilityDrift
        );
    }

    // A hostile session-wide read-only default is not silently widened. It is
    // independently attested from the current transaction mode.
    let (read_only_default_client, read_only_default_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    read_only_default_client
        .batch_execute("SET default_transaction_read_only = 'on'")
        .await?;
    assert_eq!(
        PostgresDurableAuditStatePlane::connect(
            read_only_default_client,
            test_chain_hasher.clone(),
            chain_key_epoch_id.clone(),
        )
        .await
        .err()
        .expect("a read-only session default must fail attestation"),
        StatePlaneInitializationError::CapabilityDrift
    );
    read_only_default_driver.abort();

    // The SQL readiness capability itself also fails closed when invoked from
    // an explicit read-only transaction. A constructor-owned rollback may
    // normalize such an input before attestation, but readiness never reports
    // the unnormalized transaction as writable.
    let (read_only_transaction_client, read_only_transaction_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    read_only_transaction_client
        .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
        .await?;
    read_only_transaction_client
        .batch_execute("BEGIN READ ONLY")
        .await?;
    let read_only_ready: bool = read_only_transaction_client
        .query_one(
            "SELECT ready FROM relay_state_api.audit_readiness_v1($1)",
            &[&chain_key_epoch_id.as_str()],
        )
        .await?
        .try_get("ready")?;
    assert!(!read_only_ready);
    read_only_transaction_client
        .batch_execute("ROLLBACK")
        .await?;
    drop(read_only_transaction_client);
    read_only_transaction_driver.abort();

    // The constructor owns the supplied session. It must roll back a caller's
    // live transaction before acknowledging durable writes, and must replace
    // hostile session limits before attestation. Without that normalization,
    // the write below appears inserted but is rolled back when the fixed idle
    // transaction timeout disconnects the session.
    let (open_transaction_client, open_transaction_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    open_transaction_client
        .batch_execute(
            "SET search_path = public; \
             SET lock_timeout = '0'; \
             SET statement_timeout = '0'; \
             SET idle_in_transaction_session_timeout = '0'; \
             SET synchronous_commit = 'off'; \
             SET client_encoding = 'SQL_ASCII'; \
             SET standard_conforming_strings = 'off'; \
             SET default_transaction_isolation = 'serializable'",
        )
        .await?;
    open_transaction_client.batch_execute("BEGIN").await?;
    let open_transaction_plane = PostgresDurableAuditStatePlane::connect(
        open_transaction_client,
        test_chain_hasher.clone(),
        chain_key_epoch_id.clone(),
    )
    .await?;
    assert_eq!(
        open_transaction_plane.readiness().await,
        StatePlaneReadiness::Ready
    );
    let normalized_operation_id = DurableAuditOperationId::from_ulid(Ulid::new());
    let normalized_write = attempt_write(&normalized_operation_id, "normalized-open-transaction");
    assert!(matches!(
        open_transaction_plane
            .write_phase(&normalized_write)
            .await?,
        DurableAuditWriteOutcome::Inserted(_)
    ));
    let visible_rows: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_phase \
             WHERE stream_kind = $1 AND operation_id = $2 AND phase = $3",
            &[
                &normalized_write.key().stream_kind().as_str(),
                &normalized_write.key().operation_id().as_str(),
                &normalized_write.key().phase().as_str(),
            ],
        )
        .await?
        .try_get(0)?;
    assert_eq!(
        visible_rows, 1,
        "acknowledged write must already be visible"
    );
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        open_transaction_plane.readiness().await,
        StatePlaneReadiness::Ready,
        "the session must not be killed as idle in the caller's transaction"
    );
    let durable_rows: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_phase \
             WHERE stream_kind = $1 AND operation_id = $2 AND phase = $3",
            &[
                &normalized_write.key().stream_kind().as_str(),
                &normalized_write.key().operation_id().as_str(),
                &normalized_write.key().phase().as_str(),
            ],
        )
        .await?
        .try_get(0)?;
    assert_eq!(
        durable_rows, 1,
        "acknowledged write must survive idle timeout"
    );
    drop(open_transaction_plane);
    open_transaction_driver.abort();

    // ROLLBACK is also the only command that can recover a Client in failed
    // transaction state. Constructor normalization must handle that input.
    let (failed_transaction_client, failed_transaction_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    failed_transaction_client.batch_execute("BEGIN").await?;
    let failed_transaction_error = failed_transaction_client
        .batch_execute("SELECT 1 / 0")
        .await
        .expect_err("test must leave the session in failed transaction state");
    assert_eq!(
        failed_transaction_error
            .as_db_error()
            .map(|error| error.code()),
        Some(&SqlState::DIVISION_BY_ZERO)
    );
    let failed_transaction_plane = PostgresDurableAuditStatePlane::connect(
        failed_transaction_client,
        test_chain_hasher.clone(),
        chain_key_epoch_id.clone(),
    )
    .await?;
    assert_eq!(
        failed_transaction_plane.readiness().await,
        StatePlaneReadiness::Ready
    );
    let recovered_operation_id = DurableAuditOperationId::from_ulid(Ulid::new());
    assert!(matches!(
        failed_transaction_plane
            .write_phase(&attempt_write(
                &recovered_operation_id,
                "normalized-failed-transaction",
            ))
            .await?,
        DurableAuditWriteOutcome::Inserted(_)
    ));
    drop(failed_transaction_plane);
    failed_transaction_driver.abort();

    let (client_one, driver_one) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let direct_read_error = client_one
        .query_one("SELECT count(*) FROM relay_state_private.audit_phase", &[])
        .await
        .expect_err("runtime must have no private-table privilege");
    assert_eq!(
        direct_read_error.as_db_error().map(|error| error.code()),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    let plane_one = Arc::new(
        PostgresDurableAuditStatePlane::connect(
            client_one,
            test_chain_hasher.clone(),
            chain_key_epoch_id.clone(),
        )
        .await?,
    );
    let (client_two, driver_two) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let plane_two = Arc::new(
        PostgresDurableAuditStatePlane::connect(
            client_two,
            test_chain_hasher.clone(),
            chain_key_epoch_id.clone(),
        )
        .await?,
    );
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // statement_timeout must be armed by the caller before PostgreSQL starts
    // the outer SELECT. Relay does this when it admits the runtime connection;
    // function-local settings cannot retroactively arm an in-flight statement.
    let (timeout_client, timeout_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    timeout_client
        .batch_execute(RUNTIME_SESSION_LIMITS_SQL)
        .await?;
    let timeout_started = Instant::now();
    let timeout_error = timeout_client
        .query_one(
            "SELECT pg_sleep(8), readiness.ready \
             FROM relay_state_api.audit_readiness_v1($1) AS readiness",
            &[&chain_key_epoch_id.as_str()],
        )
        .await
        .expect_err("caller-side statement timeout must cancel the outer SELECT");
    assert_eq!(
        timeout_error.as_db_error().map(|error| error.code()),
        Some(&SqlState::QUERY_CANCELED)
    );
    assert!(timeout_started.elapsed() < Duration::from_secs(7));
    drop(timeout_client);
    timeout_driver.abort();

    let (wrong_epoch_client, wrong_epoch_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    assert_eq!(
        PostgresDurableAuditStatePlane::connect(
            wrong_epoch_client,
            test_chain_hasher.clone(),
            AuditChainKeyEpochId::parse("wrong-epoch")?,
        )
        .await
        .err()
        .expect("mismatched chain epoch must fail"),
        StatePlaneInitializationError::CapabilityDrift
    );
    wrong_epoch_driver.abort();

    let operation_id = DurableAuditOperationId::from_ulid(Ulid::new());
    let write = attempt_write(&operation_id, "identical");
    let (first, second) =
        tokio::join!(plane_one.write_phase(&write), plane_two.write_phase(&write));
    let first = first?;
    let second = second?;
    assert!(matches!(
        (&first, &second),
        (
            DurableAuditWriteOutcome::Inserted(_),
            DurableAuditWriteOutcome::IdenticalDuplicate(_)
        ) | (
            DurableAuditWriteOutcome::IdenticalDuplicate(_),
            DurableAuditWriteOutcome::Inserted(_)
        )
    ));
    assert_eq!(
        first.stored_identity().envelope_id(),
        second.stored_identity().envelope_id()
    );
    assert!(matches!(
        plane_two
            .write_phase(&attempt_write(&operation_id, "conflict"))
            .await?,
        DurableAuditWriteOutcome::ConflictingDuplicate(_)
    ));

    // A snapshot held inside an explicit transaction has no cross-call lock or
    // reservation. A separate writer can advance the head while it remains open.
    let crashed_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let crashed_write = attempt_write(&crashed_operation, "crash-retry");
    let (mut crash_client, crash_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let crash_transaction = crash_client.transaction().await?;
    crash_transaction
        .batch_execute("SET LOCAL synchronous_commit = 'off'")
        .await?;
    let _candidate = direct_snapshot(&crash_transaction, &crashed_write).await?;
    assert_eq!(
        crash_transaction
            .query_one("SHOW lock_timeout", &[])
            .await?
            .try_get::<_, &str>(0)?,
        "2s"
    );
    assert_eq!(
        crash_transaction
            .query_one("SHOW statement_timeout", &[])
            .await?
            .try_get::<_, &str>(0)?,
        "5s"
    );
    assert_eq!(
        crash_transaction
            .query_one("SHOW idle_in_transaction_session_timeout", &[])
            .await?
            .try_get::<_, &str>(0)?,
        "5s"
    );
    assert_eq!(
        crash_transaction
            .query_one("SHOW synchronous_commit", &[])
            .await?
            .try_get::<_, &str>(0)?,
        "on"
    );
    let snapshot_started = Instant::now();
    assert!(matches!(
        plane_two.write_phase(&crashed_write).await?,
        DurableAuditWriteOutcome::Inserted(_)
    ));
    assert!(snapshot_started.elapsed() < Duration::from_secs(3));
    drop(crash_transaction);
    drop(crash_client);
    crash_driver.abort();
    let no_reservation_table: bool = admin
        .query_one(
            "SELECT to_regclass('relay_state_private.audit_phase_preparation') IS NULL",
            &[],
        )
        .await?
        .try_get(0)?;
    assert!(no_reservation_table);

    let attempt_identity = first.stored_identity();
    let completion = DurableAuditWrite::new(
        DurableAuditStreamKind::Consultation,
        operation_id,
        DurableAuditPhase::Completion,
        json!({
            "attempt_event": CompletionAttemptReference::from_stored_attempt(attempt_identity)
                .to_safe_payload_value(),
            "outcome": "known_complete",
        }),
    )?;
    assert!(matches!(
        plane_one.write_phase(&completion).await?,
        DurableAuditWriteOutcome::Inserted(_)
    ));
    let orphan_completion = DurableAuditWrite::new(
        DurableAuditStreamKind::Consultation,
        DurableAuditOperationId::from_ulid(Ulid::new()),
        DurableAuditPhase::Completion,
        json!({
            "attempt_event": CompletionAttemptReference::from_stored_attempt(attempt_identity)
                .to_safe_payload_value(),
            "outcome": "known_complete",
        }),
    )?;
    assert_eq!(
        plane_two.write_phase(&orphan_completion).await,
        Err(DurableAuditWriteError::StoreFailure)
    );

    let stored_envelopes = admin
        .query(
            "SELECT envelope_json FROM relay_state_private.audit_phase",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| serde_json::from_str::<AuditEnvelope>(row.get::<_, &str>(0)))
        .collect::<Result<Vec<_>, _>>()?;
    let ordered_chain = order_chain(stored_envelopes);
    let verification = verify_chain(&ordered_chain, &test_chain_hasher)?;
    assert_eq!(verification.records, 5);
    let head: Vec<u8> = admin
        .query_one(
            "SELECT record_hash FROM relay_state_private.audit_chain_head WHERE singleton = true",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(
        Some(head.as_slice()),
        verification.last_hash.as_ref().map(<[u8; 32]>::as_slice)
    );

    // A direct runtime caller can hold a successful CAS open in an explicit
    // transaction, but the function-owned limits bound both the contender and
    // the idle lock holder. The failed contender can then safely rebuild.
    let lock_holder_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let lock_holder_write = attempt_write(&lock_holder_operation, "direct-lock-holder");
    let (mut lock_client, lock_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let lock_transaction = lock_client.transaction().await?;
    let lock_candidate = direct_snapshot(&lock_transaction, &lock_holder_write).await?;
    let lock_envelope = lock_holder_write
        .build_envelope_at_chain_head(lock_candidate.predecessor, &test_chain_hasher)?;
    assert_eq!(
        direct_cas(
            &lock_transaction,
            &lock_holder_write,
            &lock_candidate,
            &lock_envelope,
        )
        .await?,
        "inserted"
    );
    for (setting, expected) in [
        ("lock_timeout", "2s"),
        ("statement_timeout", "5s"),
        ("idle_in_transaction_session_timeout", "5s"),
        ("synchronous_commit", "on"),
    ] {
        let value: String = lock_transaction
            .query_one(&format!("SHOW {setting}"), &[])
            .await?
            .try_get(0)?;
        assert_eq!(value, expected);
    }
    let blocked_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let blocked_write = attempt_write(&blocked_operation, "lock-timeout");
    let started = Instant::now();
    assert_eq!(
        plane_one.write_phase(&blocked_write).await,
        Err(DurableAuditWriteError::StoreUnavailable)
    );
    assert!(started.elapsed() < Duration::from_secs(6));
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        lock_transaction.query_one("SELECT 1", &[]).await.is_err(),
        "function-local idle timeout must terminate the explicit transaction"
    );
    drop(lock_transaction);
    drop(lock_client);
    lock_driver.abort();
    let blocked_rows: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_phase \
             WHERE operation_id = $1",
            &[&blocked_operation.as_str()],
        )
        .await?
        .get(0);
    assert_eq!(blocked_rows, 0);
    assert!(matches!(
        plane_one.write_phase(&blocked_write).await?,
        DurableAuditWriteOutcome::Inserted(_)
    ));

    // The database can validate structure and referential consistency, but it
    // cannot authenticate an external HMAC or classify arbitrary payload fields
    // as secrets. A credential holder can submit both directly; keyed verification
    // is what detects the forged chain hash.
    let arbitrary_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let arbitrary_write = DurableAuditWrite::new(
        DurableAuditStreamKind::Consultation,
        arbitrary_operation,
        DurableAuditPhase::Attempt,
        json!({
            "operator_supplied_field": {"api_key": "database-cannot-classify-this"},
            "test_marker": "direct-arbitrary-hash",
        }),
    )?;
    let (arbitrary_client, arbitrary_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let arbitrary_candidate = direct_snapshot(&arbitrary_client, &arbitrary_write).await?;
    let mut arbitrary_envelope = arbitrary_write.build_envelope_at_chain_head(
        arbitrary_candidate.predecessor,
        &AuditChainHasher::unkeyed_dev_only(),
    )?;
    arbitrary_envelope.record_hash = [0x5a; 32];
    assert_eq!(
        direct_cas(
            &arbitrary_client,
            &arbitrary_write,
            &arbitrary_candidate,
            &arbitrary_envelope,
        )
        .await?,
        "inserted"
    );
    drop(arbitrary_client);
    arbitrary_driver.abort();
    let forged_chain = order_chain(
        admin
            .query(
                "SELECT envelope_json FROM relay_state_private.audit_phase",
                &[],
            )
            .await?
            .into_iter()
            .map(|row| serde_json::from_str::<AuditEnvelope>(row.get::<_, &str>(0)))
            .collect::<Result<Vec<_>, _>>()?,
    );
    assert!(matches!(
        verify_chain(&forged_chain, &test_chain_hasher),
        Err(ChainVerificationError::RecordHashMismatch { .. })
    ));

    // A third login can be granted EXECUTE accidentally, but every API function
    // still rejects it because session_user is not the persisted runtime OID.
    admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA relay_state_api TO {attacker}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.audit_readiness_v1(text) TO {attacker};",
            attacker = quote_identifier(&attacker_role)
        ))
        .await?;
    let (attacker_client, attacker_driver) =
        postgres_client_as(&database_url, &attacker_role, &attacker_password).await?;
    let attacker_error = attacker_client
        .query_one(
            "SELECT * FROM relay_state_api.audit_readiness_v1($1)",
            &[&chain_key_epoch_id.as_str()],
        )
        .await
        .expect_err("unbound session_user must be rejected");
    assert_eq!(
        attacker_error.as_db_error().map(|error| error.code()),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE)
    );
    drop(attacker_client);
    attacker_driver.abort();
    admin
        .batch_execute(&format!(
            "REVOKE ALL ON SCHEMA relay_state_api FROM {attacker}; \
             REVOKE ALL ON FUNCTION relay_state_api.audit_readiness_v1(text) FROM {attacker};",
            attacker = quote_identifier(&attacker_role)
        ))
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // Any private ACL granted to a third role changes the exact catalog shape.
    admin
        .batch_execute(&format!(
            "GRANT SELECT ON relay_state_private.audit_phase TO {}",
            quote_identifier(&attacker_role)
        ))
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute(&format!(
            "REVOKE SELECT ON relay_state_private.audit_phase FROM {}",
            quote_identifier(&attacker_role)
        ))
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // NOINHERIT does not close SET ROLE. The installer and live capability both
    // reject even this membership before another source operation is admitted.
    let expected_visible_rows: i64 = admin
        .query_one("SELECT count(*) FROM relay_state_private.audit_phase", &[])
        .await?
        .try_get(0)?;
    admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA relay_state_private TO {reader}; \
             GRANT SELECT ON relay_state_private.audit_phase TO {reader}; \
             GRANT {reader} TO {runtime} WITH INHERIT FALSE, SET TRUE;",
            reader = quote_identifier(&private_reader_role),
            runtime = quote_identifier(&runtime_role_name),
        ))
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(&mut admin, &runtime_role, &chain_key_epoch_id).await,
        Err(StatePlaneInstallError::RuntimeRoleNotIsolated)
    );
    reset_role(&admin).await?;
    let (set_role_client, set_role_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    assert!(set_role_client
        .query_one("SELECT count(*) FROM relay_state_private.audit_phase", &[])
        .await
        .is_err());
    set_role(&set_role_client, &private_reader_role).await?;
    let visible_rows: i64 = set_role_client
        .query_one("SELECT count(*) FROM relay_state_private.audit_phase", &[])
        .await?
        .get(0);
    assert_eq!(
        visible_rows, expected_visible_rows,
        "test proves why all membership is forbidden"
    );
    reset_role(&set_role_client).await?;
    drop(set_role_client);
    set_role_driver.abort();
    admin
        .batch_execute(&format!(
            "REVOKE {reader} FROM {runtime}; \
             REVOKE SELECT ON relay_state_private.audit_phase FROM {reader}; \
             REVOKE USAGE ON SCHEMA relay_state_private FROM {reader};",
            reader = quote_identifier(&private_reader_role),
            runtime = quote_identifier(&runtime_role_name),
        ))
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // Function security/search-path and constraint/metadata fingerprints are
    // checked on every readiness and write admission.
    admin
        .batch_execute(
            "ALTER FUNCTION relay_state_api.audit_readiness_v1(text) \
             SET search_path = public",
        )
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute(
            "ALTER FUNCTION relay_state_api.audit_readiness_v1(text) \
             SET search_path = pg_catalog, relay_state_private",
        )
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    admin
        .batch_execute(
            "ALTER TABLE relay_state_private.state_plane_metadata \
                 DROP CONSTRAINT state_plane_metadata_schema_version_check; \
             ALTER TABLE relay_state_private.state_plane_metadata \
                 DROP CONSTRAINT state_plane_metadata_fingerprint_check; \
             UPDATE relay_state_private.state_plane_metadata \
                 SET schema_version = 2, capability_fingerprint = 'drifted';",
        )
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(&mut admin, &runtime_role, &chain_key_epoch_id).await,
        Err(StatePlaneInstallError::CapabilityDrift)
    );
    reset_role(&admin).await?;
    admin
        .batch_execute(&format!(
            r#"
UPDATE relay_state_private.state_plane_metadata
SET schema_version = 1, capability_fingerprint = '{fingerprint}';
ALTER TABLE relay_state_private.state_plane_metadata
    ADD CONSTRAINT state_plane_metadata_schema_version_check CHECK (schema_version = 1);
ALTER TABLE relay_state_private.state_plane_metadata
    ADD CONSTRAINT state_plane_metadata_fingerprint_check CHECK (
        capability_fingerprint = '{fingerprint}'
    );
"#,
            fingerprint = STATE_PLANE_SCHEMA_FINGERPRINT_V1,
        ))
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // Durable tables, executable table state, and their constraint-backed
    // indexes are part of the attested capability, not operational tuning.
    admin
        .batch_execute("ALTER TABLE relay_state_private.audit_phase SET UNLOGGED")
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(&mut admin, &runtime_role, &chain_key_epoch_id).await,
        Err(StatePlaneInstallError::CapabilityDrift)
    );
    reset_role(&admin).await?;
    admin
        .batch_execute("ALTER TABLE relay_state_private.audit_phase SET LOGGED")
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    admin
        .batch_execute("ALTER TABLE relay_state_private.audit_phase ENABLE ROW LEVEL SECURITY")
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute("ALTER TABLE relay_state_private.audit_phase DISABLE ROW LEVEL SECURITY")
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(
            "CREATE INDEX audit_phase_unexpected_index \
                 ON relay_state_private.audit_phase (inserted_at)",
        )
        .await?;
    reset_role(&admin).await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute("DROP INDEX relay_state_private.audit_phase_unexpected_index")
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(
            "CREATE TRIGGER audit_phase_unexpected_trigger \
                 BEFORE UPDATE ON relay_state_private.audit_phase \
                 FOR EACH ROW EXECUTE FUNCTION \
                 pg_catalog.suppress_redundant_updates_trigger()",
        )
        .await?;
    reset_role(&admin).await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute(
            "DROP TRIGGER audit_phase_unexpected_trigger \
                 ON relay_state_private.audit_phase",
        )
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(
            "CREATE RULE audit_phase_unexpected_rule AS \
                 ON INSERT TO relay_state_private.audit_phase DO INSTEAD NOTHING",
        )
        .await?;
    reset_role(&admin).await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute(
            "DROP RULE audit_phase_unexpected_rule \
                 ON relay_state_private.audit_phase",
        )
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // Defense in depth: even if a database owner defeats catalog attestation,
    // a suppressing INSERT trigger cannot advance the head while storing zero
    // phase rows.
    let suppressed_operation = DurableAuditOperationId::from_ulid(Ulid::new());
    let suppressed_write = attempt_write(&suppressed_operation, "suppressed-insert");
    let generation_before: i64 = admin
        .query_one(
            "SELECT generation FROM relay_state_private.audit_chain_head \
             WHERE singleton = true",
            &[],
        )
        .await?
        .try_get(0)?;
    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(
            r#"
CREATE FUNCTION relay_state_private.test_suppress_audit_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RETURN NULL;
END;
$function$;
CREATE TRIGGER audit_phase_suppress_insert
    BEFORE INSERT ON relay_state_private.audit_phase
    FOR EACH ROW EXECUTE FUNCTION relay_state_private.test_suppress_audit_insert();
CREATE OR REPLACE FUNCTION relay_state_private.capability_valid_v1()
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
SELECT true;
$function$;
"#,
        )
        .await?;
    reset_role(&admin).await?;
    let (suppressed_client, suppressed_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let suppressed_candidate = direct_snapshot(&suppressed_client, &suppressed_write).await?;
    let suppressed_envelope = suppressed_write
        .build_envelope_at_chain_head(suppressed_candidate.predecessor, &test_chain_hasher)?;
    assert!(direct_cas(
        &suppressed_client,
        &suppressed_write,
        &suppressed_candidate,
        &suppressed_envelope,
    )
    .await
    .is_err());
    drop(suppressed_client);
    suppressed_driver.abort();
    let suppressed_rows: i64 = admin
        .query_one(
            "SELECT count(*) FROM relay_state_private.audit_phase \
             WHERE operation_id = $1",
            &[&suppressed_operation.as_str()],
        )
        .await?
        .try_get(0)?;
    let generation_after: i64 = admin
        .query_one(
            "SELECT generation FROM relay_state_private.audit_chain_head \
             WHERE singleton = true",
            &[],
        )
        .await?
        .try_get(0)?;
    assert_eq!(suppressed_rows, 0);
    assert_eq!(generation_after, generation_before);
    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(
            "DROP TRIGGER audit_phase_suppress_insert \
                 ON relay_state_private.audit_phase; \
             DROP FUNCTION relay_state_private.test_suppress_audit_insert();",
        )
        .await?;
    admin
        .batch_execute(POSTGRES_STATE_PLANE_MIGRATION_V1)
        .await?;
    reset_role(&admin).await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    admin
        .batch_execute(&format!(
            "GRANT SELECT (envelope_json) ON relay_state_private.audit_phase TO {attacker}",
            attacker = quote_identifier(&attacker_role),
        ))
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute(&format!(
            "REVOKE SELECT (envelope_json) ON relay_state_private.audit_phase FROM {attacker}",
            attacker = quote_identifier(&attacker_role),
        ))
        .await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // A stale function owner is detected even if every other object is intact.
    admin
        .batch_execute(&format!(
            "ALTER FUNCTION relay_state_api.audit_readiness_v1(text) OWNER TO {}",
            quote_identifier(&stale_owner_role)
        ))
        .await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    admin
        .batch_execute(&format!(
            "ALTER FUNCTION relay_state_api.audit_readiness_v1(text) OWNER TO {owner};",
            owner = quote_identifier(&owner_role),
        ))
        .await?;
    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(&format!(
            "REVOKE ALL ON FUNCTION relay_state_api.audit_readiness_v1(text) FROM PUBLIC; \
             REVOKE ALL ON FUNCTION relay_state_api.audit_readiness_v1(text) FROM {runtime}; \
             GRANT EXECUTE ON FUNCTION relay_state_api.audit_readiness_v1(text) TO {runtime};",
            runtime = quote_identifier(&runtime_role_name),
        ))
        .await?;
    reset_role(&admin).await?;
    assert_eq!(plane_one.readiness().await, StatePlaneReadiness::Ready);

    // Renaming one OUT column changes the function ABI. Runtime row decoding
    // must fail closed without panicking, and migration preflight must reject
    // the drift rather than overwriting it.
    set_role(&admin, &owner_role).await?;
    admin
        .batch_execute(&format!(
            r#"
DROP FUNCTION relay_state_api.audit_readiness_v1(text);
CREATE FUNCTION relay_state_api.audit_readiness_v1(
    p_expected_chain_key_epoch_id text
)
RETURNS TABLE (
    is_ready boolean,
    capability_id text,
    capability_fingerprint text,
    owner_role_oid bigint,
    runtime_role_oid bigint,
    chain_key_epoch_id text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    RETURN QUERY
    SELECT relay_state_private.capability_valid_v1()
           AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id,
           metadata.capability_id,
           metadata.capability_fingerprint,
           metadata.owner_role_oid::bigint,
           metadata.runtime_role_oid::bigint,
           metadata.chain_key_epoch_id
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
END;
$function$;
REVOKE ALL ON FUNCTION relay_state_api.audit_readiness_v1(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION relay_state_api.audit_readiness_v1(text) TO {runtime};
"#,
            runtime = quote_identifier(&runtime_role_name),
        ))
        .await?;
    reset_role(&admin).await?;
    assert_eq!(
        plane_one.readiness().await,
        StatePlaneReadiness::Unavailable
    );
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(&mut admin, &runtime_role, &chain_key_epoch_id).await,
        Err(StatePlaneInstallError::CapabilityDrift)
    );
    reset_role(&admin).await?;

    drop(plane_one);
    drop(plane_two);
    driver_one.abort();
    driver_two.abort();
    let _ = driver_one.await;
    let _ = driver_two.await;
    admin
        .batch_execute(
            "DROP SCHEMA relay_state_api CASCADE; DROP SCHEMA relay_state_private CASCADE;",
        )
        .await?;
    for role in [
        &runtime_role_name,
        &private_reader_role,
        &attacker_role,
        &bridge_role,
        &owner_role,
        &stale_owner_role,
    ] {
        admin
            .batch_execute(&format!(
                "DROP OWNED BY {role}; DROP ROLE {role};",
                role = quote_identifier(role)
            ))
            .await?;
    }
    admin
        .execute("SELECT pg_advisory_unlock($1)", &[&TEST_ADVISORY_LOCK])
        .await?;
    admin_driver.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL with max_prepared_transactions > 0"]
async fn postgres_state_plane_rejects_prepared_transaction_capability(
) -> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = env::var(PREPARED_DATABASE_URL_ENV) else {
        eprintln!("SKIPPED: {PREPARED_DATABASE_URL_ENV} is not set");
        return Ok(());
    };
    let (mut admin, admin_driver) = postgres_client(&database_url).await?;
    admin
        .execute("SELECT pg_advisory_lock($1)", &[&TEST_ADVISORY_LOCK])
        .await?;
    admin
        .batch_execute(
            "DROP SCHEMA IF EXISTS relay_state_api CASCADE; \
             DROP SCHEMA IF EXISTS relay_state_private CASCADE;",
        )
        .await?;
    let configured: i32 = admin
        .query_one(
            "SELECT current_setting('max_prepared_transactions')::integer",
            &[],
        )
        .await?
        .try_get(0)?;
    assert!(configured > 0);

    let owner_role = role_name("prepared_owner");
    let runtime_role_name = role_name("prepared_runtime");
    let runtime_password = Ulid::new().to_string();
    let database_name: String = admin
        .query_one("SELECT current_database()", &[])
        .await?
        .try_get(0)?;
    admin
        .batch_execute(&format!(
            "CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB \
                 NOREPLICATION NOBYPASSRLS; \
             CREATE ROLE {runtime} LOGIN PASSWORD '{runtime_password}' \
                 NOSUPERUSER NOCREATEROLE NOCREATEDB \
                 NOREPLICATION NOBYPASSRLS; \
             GRANT CREATE ON DATABASE {database} TO {owner};",
            owner = quote_identifier(&owner_role),
            runtime = quote_identifier(&runtime_role_name),
            runtime_password = runtime_password,
            database = quote_identifier(&database_name),
        ))
        .await?;
    let runtime_role = RuntimeDatabaseRole::parse(&runtime_role_name)?;
    let chain_key_epoch_id = AuditChainKeyEpochId::parse("prepared-rejection-epoch")?;
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(&mut admin, &runtime_role, &chain_key_epoch_id).await,
        Err(StatePlaneInstallError::UnsafeDatabaseConfiguration)
    );

    // Simulate a previously valid catalog observed after a restart that
    // enabled prepared transactions. The installer cannot create this state
    // under the unsafe setting, but readiness must independently reject it.
    seed_catalog_for_unsafe_restart(&admin, &runtime_role_name, &chain_key_epoch_id).await?;
    reset_role(&admin).await?;

    let (readiness_client, readiness_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let readiness = readiness_client
        .query_one(
            "SELECT * FROM relay_state_api.audit_readiness_v1($1)",
            &[&chain_key_epoch_id.as_str()],
        )
        .await?;
    assert!(!readiness.try_get::<_, bool>("ready")?);
    drop(readiness_client);
    readiness_driver.abort();

    let secret_env = format!(
        "REGISTRY_RELAY_STATE_PLANE_PREPARED_SECRET_{}",
        Ulid::new().to_string()
    );
    env::set_var(
        &secret_env,
        "prepared-restart-test-chain-secret-at-least-thirty-two-bytes",
    );
    let chain_hasher = AuditChainHasher::from_env(&secret_env)?;
    env::remove_var(&secret_env);
    let (runtime_client, runtime_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    assert_eq!(
        PostgresDurableAuditStatePlane::connect(runtime_client, chain_hasher, chain_key_epoch_id,)
            .await
            .err()
            .expect("runtime capability must reject prepared transactions after restart"),
        StatePlaneInitializationError::CapabilityDrift
    );
    runtime_driver.abort();

    admin
        .batch_execute(
            "DROP SCHEMA relay_state_api CASCADE; \
             DROP SCHEMA relay_state_private CASCADE;",
        )
        .await?;
    for role in [&runtime_role_name, &owner_role] {
        admin
            .batch_execute(&format!(
                "DROP OWNED BY {role}; DROP ROLE {role};",
                role = quote_identifier(role)
            ))
            .await?;
    }
    admin
        .execute("SELECT pg_advisory_unlock($1)", &[&TEST_ADVISORY_LOCK])
        .await?;
    admin_driver.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL with fsync or full_page_writes disabled"]
async fn postgres_state_plane_rejects_unsafe_wal_durability(
) -> Result<(), Box<dyn std::error::Error>> {
    let Ok(database_url) = env::var(UNSAFE_DURABILITY_DATABASE_URL_ENV) else {
        eprintln!("SKIPPED: {UNSAFE_DURABILITY_DATABASE_URL_ENV} is not set");
        return Ok(());
    };
    let (mut admin, admin_driver) = postgres_client(&database_url).await?;
    admin
        .execute("SELECT pg_advisory_lock($1)", &[&TEST_ADVISORY_LOCK])
        .await?;
    admin
        .batch_execute(
            "DROP SCHEMA IF EXISTS relay_state_api CASCADE; \
             DROP SCHEMA IF EXISTS relay_state_private CASCADE;",
        )
        .await?;
    let durability = admin
        .query_one(
            "SELECT current_setting('fsync') = 'on' AS fsync_safe, \
                    current_setting('full_page_writes') = 'on' AS page_writes_safe",
            &[],
        )
        .await?;
    assert!(
        !durability.try_get::<_, bool>("fsync_safe")?
            || !durability.try_get::<_, bool>("page_writes_safe")?
    );

    let owner_role = role_name("durability_owner");
    let runtime_role_name = role_name("durability_runtime");
    let runtime_password = Ulid::new().to_string();
    let database_name: String = admin
        .query_one("SELECT current_database()", &[])
        .await?
        .try_get(0)?;
    admin
        .batch_execute(&format!(
            "CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB \
                 NOREPLICATION NOBYPASSRLS; \
             CREATE ROLE {runtime} LOGIN PASSWORD '{runtime_password}' \
                 NOSUPERUSER NOCREATEROLE NOCREATEDB \
                 NOREPLICATION NOBYPASSRLS; \
             GRANT CREATE ON DATABASE {database} TO {owner};",
            owner = quote_identifier(&owner_role),
            runtime = quote_identifier(&runtime_role_name),
            runtime_password = runtime_password,
            database = quote_identifier(&database_name),
        ))
        .await?;
    let runtime_role = RuntimeDatabaseRole::parse(&runtime_role_name)?;
    let chain_key_epoch_id = AuditChainKeyEpochId::parse("unsafe-durability-epoch")?;
    set_role(&admin, &owner_role).await?;
    assert_eq!(
        install_postgres_state_plane_v1(&mut admin, &runtime_role, &chain_key_epoch_id).await,
        Err(StatePlaneInstallError::UnsafeDatabaseConfiguration)
    );
    seed_catalog_for_unsafe_restart(&admin, &runtime_role_name, &chain_key_epoch_id).await?;
    reset_role(&admin).await?;
    let (runtime_client, runtime_driver) =
        postgres_client_as(&database_url, &runtime_role_name, &runtime_password).await?;
    let readiness = runtime_client
        .query_one(
            "SELECT * FROM relay_state_api.audit_readiness_v1($1)",
            &[&chain_key_epoch_id.as_str()],
        )
        .await?;
    assert!(!readiness.try_get::<_, bool>("ready")?);
    drop(runtime_client);
    runtime_driver.abort();
    admin
        .batch_execute(
            "DROP SCHEMA relay_state_api CASCADE; \
             DROP SCHEMA relay_state_private CASCADE;",
        )
        .await?;
    for role in [&runtime_role_name, &owner_role] {
        admin
            .batch_execute(&format!(
                "DROP OWNED BY {role}; DROP ROLE {role};",
                role = quote_identifier(role)
            ))
            .await?;
    }
    admin
        .execute("SELECT pg_advisory_unlock($1)", &[&TEST_ADVISORY_LOCK])
        .await?;
    admin_driver.abort();
    Ok(())
}
