// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    fetch_discovery_with_policy, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig,
};
use registry_platform_testing::{
    fixtures as testing_fixtures, jwks_from_private_jwk, sign_ed25519_compact_jwt, MockIdp,
};
use registry_server::compiler::{compile_project, module_digest, CompileProfile};
use registry_server::contract::{parse_module_yaml, parse_project_yaml};
use registry_server::migration::{
    apply_verified_package, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest,
};
use registry_server::package::{
    load_package, prepare_package, PackageBuildRequest, PackageIntent, PackageLoadContext,
    PackageMigrationPlanInput, PackageModuleSource, PackageSignature, PackageSourceFile,
    PackageTrustAnchor, SignaturePolicy, TrustAnchorKey, VerifiedPackage, TRUST_ANCHOR_API_VERSION,
};
use registry_server::postgres::{
    initialize_registry_state_for_catalog_test, install_compiled_schema,
    managed_schema_fingerprint, verify_runtime_role, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, RegistryStateTestIdentity,
};
use registry_server::startup::{
    prepare_with_connection_and_key_source_for_test, prepare_with_connection_config_for_test,
    serve_until_shutdown, PreparedServer, StartupError,
};
use serde::Serialize;
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::oneshot;
use tokio_postgres::GenericClient;
use tower::ServiceExt as _;

const INSTANCE: &str = "startup-instance";
const DATABASE: &str = "startup-database";
const SOURCE_REVISION: &str = "startup-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: neutral-record-list
    steps:
      - id: list-neutral-records
        entity: neutral-record
        accessProfile: reader
        claims: {principal: package-reader}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_server_wires_services_and_static_jwks_readiness_tracks_database() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    verify_runtime_role(&migration, &database.migration_role)
        .await
        .expect_err("migration connection is not accepted as runtime");

    let fixture = StartupFixture::new();
    let signing =
        generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("fixture signing key generates");
    let provisional = PackageFixture::build(&fixture.root, fingerprint(1), &signing);
    let provisional_context = provisional.context(PackageIntent::InitialActivation);
    let verified_provisional = load_package(&provisional.root, &provisional_context)
        .expect("provisional package loads enough to install schema");
    install_compiled_schema(
        &migration,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("compiled schema installs");
    let expected_catalog = ExpectedManagedCatalog::compiled(verified_provisional.registry());
    let schema_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("compiled schema fingerprints");
    drop(provisional);

    let package = PackageFixture::build(&fixture.root, schema_fingerprint, &signing);
    let context = package.context(PackageIntent::InitialActivation);
    let verified = load_package(&package.root, &context).expect("final package verifies");
    initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified.registry()),
        RegistryStateTestIdentity {
            package_id: &verified.manifest().package_id,
            environment: &verified.manifest().environment,
            instance_id: &verified.manifest().instance_id,
            database_id: &verified.manifest().database_id,
            package_revision: &verified.manifest().package_revision,
            package_sequence: i64::try_from(verified.manifest().sequence)
                .expect("fixture sequence fits"),
        },
    )
    .await
    .expect("Registry state initializes");
    migration_task.abort();

    let idp = MockIdp::start().await;
    let config_path = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    let prepared =
        prepare_with_connection_config_for_test(&config_path, database.runtime_config.clone())
            .await
            .expect("prepared server verifies package, database, audit, and OIDC");
    assert_ready(&prepared, StatusCode::OK).await;
    assert_unknown_static_kid_refuses_value_free(&prepared).await;

    let wrong_role_path = fixture.write_static_jwks_config(
        &package,
        &database.migration_role,
        &database.intruder_role,
        &idp,
        Some("0123456789abcdef0123456789abcdef"),
    );
    assert_eq!(
        prepare_with_connection_config_for_test(&wrong_role_path, database.runtime_config.clone())
            .await
            .err(),
        Some(StartupError::DatabaseUnready)
    );

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
             SET active_package_revision = $1
             WHERE singleton",
            &[&"sha256:0000000000000000000000000000000000000000000000000000000000000000"],
        )
        .await
        .expect("test invalidates active package");
    assert_ready(&prepared, StatusCode::SERVICE_UNAVAILABLE).await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
             SET active_package_revision = $1
             WHERE singleton",
            &[&verified.manifest().package_revision],
        )
        .await
        .expect("test restores active package");
    assert_ready(&prepared, StatusCode::OK).await;
    idp.stop().await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_ready(&prepared, StatusCode::OK).await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn live_old_server_drains_apply_and_exact_successor_restart_becomes_ready() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let fixture = StartupFixture::new();
    let signing =
        generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("fixture signing key generates");

    let provisional = PackageFixture::build(&fixture.root, fingerprint(1), &signing);
    let verified_provisional = load_package(
        &provisional.root,
        &provisional.context(PackageIntent::InitialActivation),
    )
    .expect("provisional initial package verifies");
    let transaction = migration
        .transaction()
        .await
        .expect("initial fingerprint transaction starts");
    install_compiled_schema(
        &transaction,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("initial schema rehearses");
    let initial_fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified_provisional.registry()),
    )
    .await
    .expect("initial target fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("initial rehearsal rolls back");
    drop(provisional);

    let initial_package = PackageFixture::build(&fixture.root, initial_fingerprint, &signing);
    let verified_initial = load_package(
        &initial_package.root,
        &initial_package.context(PackageIntent::InitialActivation),
    )
    .expect("final initial package verifies");
    let initial = apply_startup_package(
        &database,
        &verified_initial,
        ApplyPrecondition::InitialActivation,
    )
    .await;

    let provisional_successor = PackageFixture::build_successor(
        &fixture.root,
        fingerprint(2),
        &signing,
        &initial.package_revision,
    );
    let activation_intent = PackageIntent::Activation {
        active_revision: &initial.package_revision,
        active_sequence: 1,
    };
    let verified_provisional_successor = load_package(
        &provisional_successor.root,
        &provisional_successor.context(activation_intent),
    )
    .expect("provisional successor verifies");
    let transaction = migration
        .transaction()
        .await
        .expect("successor fingerprint transaction starts");
    for statement in &verified_provisional_successor
        .manifest()
        .migration_plan
        .statements
    {
        transaction
            .batch_execute(&statement.sql)
            .await
            .expect("successor statement rehearses");
    }
    let added_table =
        &verified_provisional_successor.registry().entities()["second-record"].physical_table;
    transaction
        .batch_execute(&format!(
            "REVOKE ALL ON TABLE registry_data.{} FROM PUBLIC, \"{}\";
             GRANT SELECT ON TABLE registry_data.{} TO \"{}\";",
            quote(added_table),
            database.runtime_role.as_str(),
            quote(added_table),
            database.runtime_role.as_str(),
        ))
        .await
        .expect("successor rehearsal installs the compiled runtime ACL");
    let successor_fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified_provisional_successor.registry()),
    )
    .await
    .expect("successor target fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("successor rehearsal rolls back");
    drop(provisional_successor);

    let successor_package = PackageFixture::build_successor(
        &fixture.root,
        successor_fingerprint,
        &signing,
        &initial.package_revision,
    );
    let verified_successor = load_package(
        &successor_package.root,
        &successor_package.context(activation_intent),
    )
    .expect("final successor verifies");
    migration_task.abort();

    let record_id = uuid::Uuid::from_u128(1);
    let old_entity = &verified_initial.registry().entities()["neutral-record"];
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.{} (record_id, active_package_revision, {})
                 VALUES ($1, $2, $3)",
                quote(&old_entity.physical_table),
                quote(&old_entity.fields["code"].physical_name),
            ),
            &[&record_id, &initial.package_revision, &"old-row"],
        )
        .await
        .expect("old package row seeds");

    let idp = MockIdp::start().await;
    let key_source = mock_idp_key_source(&idp).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock follows epoch")
        .as_secs();
    let token = idp.mint_token(json!({
        "aud": "urn:registry-server:test",
        "principal": "recovery-operator",
        "iat": now,
        "nbf": now,
        "exp": now + 120
    }));
    let old_address = reserve_address();
    let old_config = fixture.write_config_at(
        &initial_package,
        &database.migration_role,
        &database.runtime_role,
        &idp.issuer(),
        Some("0123456789abcdef0123456789abcdef"),
        old_address,
    );
    let old_prepared = prepare_with_connection_and_key_source_for_test(
        &old_config,
        database.runtime_config.clone(),
        Arc::clone(&key_source),
    )
    .await
    .expect("old exact package prepares");
    let (old_shutdown, old_server) = spawn_live_server(old_prepared, old_address).await;

    let (mut record_blocker_connection, record_blocker_task) = database.connect_migration().await;
    let record_blocker = record_blocker_connection
        .transaction()
        .await
        .expect("record blocker transaction starts");
    record_blocker
        .batch_execute(&format!(
            "LOCK TABLE registry_data.{} IN ACCESS EXCLUSIVE MODE",
            quote(&old_entity.physical_table)
        ))
        .await
        .expect("record blocker owns the old data table");

    let (mut ddl_blocker_connection, ddl_blocker_task) = database.connect_migration().await;
    let ddl_blocker = ddl_blocker_connection
        .transaction()
        .await
        .expect("DDL blocker transaction starts");
    let create_table_sql = verified_successor
        .manifest()
        .migration_plan
        .statements
        .iter()
        .find(|statement| statement.sql.starts_with("CREATE TABLE "))
        .expect("successor has one table creation")
        .sql
        .clone();
    ddl_blocker
        .batch_execute(&create_table_sql)
        .await
        .expect("uncommitted successor table blocks exact apply DDL");

    let record_path = format!("/v1/records/neutral-records/{record_id}?accessProfile=reader");
    let in_flight_address = old_address;
    let in_flight_path = record_path.clone();
    let in_flight_token = token.clone();
    let mut in_flight = tokio::spawn(async move {
        http_get(in_flight_address, &in_flight_path, Some(&in_flight_token)).await
    });
    tokio::select! {
        result = &mut in_flight => {
            let response = result
                .expect("premature in-flight task joins")
                .expect("premature in-flight HTTP exchange completes");
            panic!(
                "old record request returned before reaching its deterministic table wait with status {}",
                response.status
            );
        }
        () = wait_for_role_relation_wait(&database.admin, database.runtime_role.as_str()) => {}
    }

    let active = {
        let apply = apply_startup_package_result(
            &database,
            &verified_successor,
            ApplyPrecondition::Successor { current: &initial },
        );
        tokio::pin!(apply);
        tokio::select! {
            result = &mut apply => panic!("apply passed the prior in-flight record operation: {result:?}"),
            () = wait_for_role_advisory_wait(&database.admin, database.migration_role.as_str()) => {}
        }
        record_blocker
            .rollback()
            .await
            .expect("operator releases the deterministic record blocker");
        record_blocker_task.abort();
        let drained = tokio::time::timeout(Duration::from_secs(2), in_flight)
            .await
            .expect("prior in-flight request drains within the bound")
            .expect("prior in-flight task joins")
            .expect("prior in-flight HTTP exchange completes");
        // Apply wins only after the record transaction releases its shared
        // lock. If that happens before the terminal audit can gate release,
        // the held old-package bytes are discarded as a value-free refusal.
        assert_eq!(drained.status, 503);
        assert!(!drained.body.contains("old-row"));
        assert!(!drained.body.contains("recovery-operator"));
        assert!(!drained.body.contains(&token));

        tokio::select! {
            result = &mut apply => panic!("apply escaped the deterministic successor DDL blocker: {result:?}"),
            () = wait_for_maintenance_without_sleep(&database.admin, "applying") => {}
        }
        let refused_during_apply = tokio::time::timeout(
            Duration::from_secs(2),
            http_get(old_address, &record_path, Some(&token)),
        )
        .await
        .expect("new record work fails within the configured lock bound")
        .expect("old server returns a value-free refusal");
        assert_eq!(refused_during_apply.status, 503);
        assert!(!refused_during_apply.body.contains("old-row"));
        assert!(!refused_during_apply.body.contains("recovery-operator"));
        assert!(!refused_during_apply.body.contains(&token));

        ddl_blocker
            .rollback()
            .await
            .expect("operator releases the deterministic successor DDL blocker");
        ddl_blocker_task.abort();
        apply
            .await
            .expect("exact successor applies after prior work drains")
    };
    assert_eq!(
        active.package_revision,
        verified_successor.manifest().package_revision
    );

    let old_ready = http_get(old_address, "/ready", None)
        .await
        .expect("old process readiness responds after activation");
    assert_eq!(old_ready.status, 503);

    let (mut post_activation_blocker, post_activation_blocker_task) =
        database.connect_migration().await;
    let post_activation_lock = post_activation_blocker
        .transaction()
        .await
        .expect("post-activation record blocker starts");
    post_activation_lock
        .batch_execute(&format!(
            "LOCK TABLE registry_data.{} IN ACCESS EXCLUSIVE MODE",
            quote(&old_entity.physical_table)
        ))
        .await
        .expect("old record table is unavailable to prove pre-I/O refusal");
    let old_refusal = tokio::time::timeout(
        Duration::from_millis(750),
        http_get(old_address, &record_path, Some(&token)),
    )
    .await
    .expect("old process refuses before attempting blocked record I/O")
    .expect("old process returns its refusal");
    assert_eq!(old_refusal.status, 503);
    assert!(!old_refusal.body.contains("old-row"));
    assert!(!old_refusal.body.contains("recovery-operator"));
    assert!(!old_refusal.body.contains(&token));
    post_activation_lock
        .rollback()
        .await
        .expect("post-activation record blocker rolls back");
    post_activation_blocker_task.abort();

    old_shutdown
        .send(())
        .expect("old process shutdown signal sends");
    old_server
        .await
        .expect("old server task joins")
        .expect("old server shuts down cleanly");

    let new_address = reserve_address();
    let new_config = fixture.write_config_at(
        &successor_package,
        &database.migration_role,
        &database.runtime_role,
        &idp.issuer(),
        Some("0123456789abcdef0123456789abcdef"),
        new_address,
    );
    let new_prepared = prepare_with_connection_and_key_source_for_test(
        &new_config,
        database.runtime_config.clone(),
        key_source,
    )
    .await
    .expect("restart accepts only the exact active successor package");
    let (new_shutdown, new_server) = spawn_live_server(new_prepared, new_address).await;
    assert_eq!(
        http_get(new_address, "/ready", None)
            .await
            .expect("new process readiness responds")
            .status,
        200
    );
    new_shutdown
        .send(())
        .expect("new process shutdown signal sends");
    new_server
        .await
        .expect("new server task joins")
        .expect("new server shuts down cleanly");

    idp.stop().await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_and_oidc_failures_refuse_before_listener_bind() {
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    let fixture = StartupFixture::new();
    let signing =
        generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("fixture signing key generates");
    let provisional = PackageFixture::build(&fixture.root, fingerprint(1), &signing);
    let verified_provisional = load_package(
        &provisional.root,
        &provisional.context(PackageIntent::InitialActivation),
    )
    .expect("provisional package loads");
    install_compiled_schema(
        &migration,
        verified_provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("compiled schema installs");
    let catalog = ExpectedManagedCatalog::compiled(verified_provisional.registry());
    let schema_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &catalog)
            .await
            .expect("compiled schema fingerprints");
    drop(provisional);

    let package = PackageFixture::build(&fixture.root, schema_fingerprint, &signing);
    let verified = load_package(
        &package.root,
        &package.context(PackageIntent::InitialActivation),
    )
    .expect("final package verifies");
    initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(verified.registry()),
        RegistryStateTestIdentity {
            package_id: &verified.manifest().package_id,
            environment: &verified.manifest().environment,
            instance_id: &verified.manifest().instance_id,
            database_id: &verified.manifest().database_id,
            package_revision: &verified.manifest().package_revision,
            package_sequence: 1,
        },
    )
    .await
    .expect("Registry state initializes");
    migration_task.abort();

    let missing_audit_path = fixture.write_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        "http://127.0.0.1:9",
        None,
    );
    assert_eq!(
        prepare_with_connection_config_for_test(
            &missing_audit_path,
            database.runtime_config.clone()
        )
        .await
        .err(),
        Some(StartupError::Audit)
    );

    let bad_oidc_path = fixture.write_config(
        &package,
        &database.migration_role,
        &database.runtime_role,
        "http://127.0.0.1:9",
        Some("0123456789abcdef0123456789abcdef"),
    );
    assert_eq!(
        prepare_with_connection_config_for_test(&bad_oidc_path, database.runtime_config.clone())
            .await
            .err(),
        Some(StartupError::Oidc)
    );
    database.cleanup().await;
}

async fn apply_startup_package(
    database: &TestDatabase,
    package: &VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
) -> ExpectedRegistryIdentity {
    apply_startup_package_result(database, package, precondition)
        .await
        .expect("verified package applies")
}

async fn apply_startup_package_result(
    database: &TestDatabase,
    package: &VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
) -> registry_server::migration::Result<ExpectedRegistryIdentity> {
    apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        package,
        precondition,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
            .expect("test apply timeouts are bounded"),
    ))
    .await
}

struct LiveHttpResponse {
    status: u16,
    body: String,
}

fn reserve_address() -> SocketAddr {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("loopback address reservation binds");
    listener
        .local_addr()
        .expect("loopback reservation address reads")
}

async fn spawn_live_server(
    prepared: PreparedServer,
    address: SocketAddr,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), StartupError>>,
) {
    assert_eq!(prepared.bind(), address);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut task = tokio::spawn(serve_until_shutdown(prepared, async move {
        let _ = shutdown_rx.await;
        Ok(())
    }));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                result = &mut task => {
                    panic!("live PreparedServer stopped before its health route was reachable: {result:?}")
                }
                connection = tokio::net::TcpStream::connect(address) => {
                    if connection.is_ok() {
                        return;
                    }
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("live PreparedServer accepts HTTP without timing sleeps");
    (shutdown_tx, task)
}

async fn http_get(
    address: SocketAddr,
    path: &str,
    token: Option<&str>,
) -> std::io::Result<LiveHttpResponse> {
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    let authorization = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {address}\r\n{authorization}Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    loop {
        let read = stream.read_buf(&mut response).await?;
        if read == 0 || complete_http_response(&response) {
            break;
        }
    }
    let response = String::from_utf8(response)
        .map_err(|_| std::io::Error::other("HTTP response is not UTF-8"))?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("HTTP response is incomplete"))?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other("HTTP response status is invalid"))?;
    Ok(LiveHttpResponse {
        status,
        body: body.to_owned(),
    })
}

fn complete_http_response(response: &[u8]) -> bool {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    length.is_some_and(|length| response.len() >= header_end + 4 + length)
}

async fn wait_for_role_relation_wait(client: &impl GenericClient, role: &str) {
    wait_for_role_lock(client, role, "relation").await;
}

async fn wait_for_role_advisory_wait(client: &impl GenericClient, role: &str) {
    wait_for_role_lock(client, role, "advisory").await;
}

async fn wait_for_role_lock(client: &impl GenericClient, role: &str, lock_type: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let waiting: bool = client
                .query_one(
                    "SELECT EXISTS (
                         SELECT 1
                         FROM pg_locks AS lock
                         JOIN pg_stat_activity AS activity USING (pid)
                         WHERE activity.datname = current_database()
                           AND activity.usename = $1
                           AND lock.locktype = $2
                           AND NOT lock.granted
                     )",
                    &[&role, &lock_type],
                )
                .await
                .expect("administrator observes lock waits")
                .get(0);
            if waiting {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the expected database lock wait is reached without timing sleeps");
}

async fn wait_for_maintenance_without_sleep(client: &impl GenericClient, expected: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let status: String = client
                .query_one(
                    "SELECT maintenance_status
                     FROM registry_internal.registry_state
                     WHERE singleton",
                    &[],
                )
                .await
                .expect("maintenance state reads")
                .get(0);
            if status == expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("maintenance reaches its durable state without timing sleeps");
}

async fn assert_ready(prepared: &PreparedServer, expected: StatusCode) {
    let response = prepared
        .app()
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), expected);
}

async fn assert_unknown_static_kid_refuses_value_free(prepared: &PreparedServer) {
    const UNKNOWN_KID_CANARY: &str = "unknown-static-kid-canary";
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock follows epoch")
        .as_secs();
    let token = sign_ed25519_compact_jwt(
        testing_fixtures::ED25519_PRIVATE_JWK,
        "JWT",
        UNKNOWN_KID_CANARY,
        json!({
            "aud": "urn:registry-server:test",
            "principal": "package-reader",
            "iat": now,
            "nbf": now,
            "exp": now + 120
        }),
    );
    let response = prepared
        .app()
        .oneshot(
            Request::builder()
                .uri("/v1/records/neutral-records?accessProfile=reader")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let mut rendered = response
        .headers()
        .iter()
        .map(|(name, value)| format!("{}:{}\n", name, value.to_str().unwrap_or("<binary>")))
        .collect::<String>();
    rendered.push_str(
        std::str::from_utf8(
            &to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("response body reads"),
        )
        .expect("response body is UTF-8"),
    );
    assert!(!rendered.contains(UNKNOWN_KID_CANARY));
}

async fn mock_idp_key_source(idp: &MockIdp) -> Arc<JwksFetcher> {
    let discovery = fetch_discovery_with_policy(
        &OidcDiscoveryConfig {
            issuer: idp.issuer(),
            jwks_uri_override: None,
            discovery_timeout: Duration::from_secs(5),
            max_doc_bytes: 16 * 1024,
        },
        &FetchUrlPolicy::dev(),
    )
    .await
    .expect("MockIdp discovery fetch succeeds");
    Arc::new(JwksFetcher::new_with_fetch_url_policy(
        discovery.jwks_uri,
        JwksFetcherConfig {
            cache_ttl: Duration::from_secs(1),
            negative_cache_ttl: Duration::from_secs(1),
            refresh_cooldown: Duration::from_secs(1),
            max_doc_bytes: 16 * 1024,
            request_timeout: Duration::from_secs(5),
            outage_tolerance: Duration::ZERO,
        },
        FetchUrlPolicy::dev(),
    ))
}

struct StartupFixture {
    root: PathBuf,
    secret_root: PathBuf,
}

impl StartupFixture {
    fn new() -> Self {
        let parent = std::env::temp_dir()
            .canonicalize()
            .expect("temporary parent canonicalizes");
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock follows epoch")
            .as_nanos();
        let ordinal = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = parent.join(format!(
            "registry-server-postgres-startup-{}-{suffix}-{ordinal}",
            std::process::id(),
        ));
        fs::create_dir(&root).expect("fixture root creates");
        let secret_root = root.join("secrets");
        fs::create_dir(&secret_root).expect("secret root creates");
        Self { root, secret_root }
    }

    fn write_config(
        &self,
        package: &PackageFixture,
        migration_role: &registry_server::postgres::SqlIdentifier,
        runtime_role: &registry_server::postgres::SqlIdentifier,
        issuer: &str,
        audit_key: Option<&str>,
    ) -> PathBuf {
        self.write_config_at(
            package,
            migration_role,
            runtime_role,
            issuer,
            audit_key,
            "127.0.0.1:9".parse().expect("fixture listener parses"),
        )
    }

    fn write_static_jwks_config(
        &self,
        package: &PackageFixture,
        migration_role: &registry_server::postgres::SqlIdentifier,
        runtime_role: &registry_server::postgres::SqlIdentifier,
        idp: &MockIdp,
        audit_key: Option<&str>,
    ) -> PathBuf {
        let public_jwks = jwks_from_private_jwk(
            &PrivateJwk::parse(testing_fixtures::ED25519_PRIVATE_JWK).expect("test IdP key parses"),
        );
        let jwks_path = self.secret_root.join("oidc-jwks");
        fs::write(
            &jwks_path,
            serde_json::to_vec(&public_jwks).expect("static JWKS serializes"),
        )
        .expect("static JWKS writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&jwks_path, fs::Permissions::from_mode(0o600))
                .expect("static JWKS permissions set");
        }
        let path = self.write_config(
            package,
            migration_role,
            runtime_role,
            &idp.issuer(),
            audit_key,
        );
        let raw = fs::read_to_string(&path).expect("runtime config reads");
        fs::write(
            &path,
            raw.replace(
                "    jwksCache:\n",
                "    jwksSource:\n      kind: static\n      documentRef: secret:file/oidc-jwks\n    jwksCache:\n",
            ),
        )
        .expect("static JWKS runtime config writes");
        path
    }

    fn write_config_at(
        &self,
        package: &PackageFixture,
        migration_role: &registry_server::postgres::SqlIdentifier,
        runtime_role: &registry_server::postgres::SqlIdentifier,
        issuer: &str,
        audit_key: Option<&str>,
        listener: SocketAddr,
    ) -> PathBuf {
        let hash_key_ref = if let Some(audit_key) = audit_key {
            let audit_key_path = self.secret_root.join("audit-key");
            fs::write(&audit_key_path, audit_key).expect("audit key writes");
            let cursor_key_path = self.secret_root.join("cursor-key");
            fs::write(&cursor_key_path, [0x53_u8; 32]).expect("cursor key writes");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&audit_key_path, fs::Permissions::from_mode(0o600))
                    .expect("audit key permissions set");
                fs::set_permissions(&cursor_key_path, fs::Permissions::from_mode(0o600))
                    .expect("cursor key permissions set");
            }
            "secret:file/audit-key"
        } else {
            "secret:file/missing-audit-key"
        };
        let ordinal = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = self.root.join(format!("runtime-{ordinal}.yaml"));
        fs::write(
            &path,
            format!(
                r#"
listener:
  bind: {listener}
  trustedProxy: direct
identity:
  environment: production
  instanceId: {INSTANCE}
  databaseId: {DATABASE}
  databaseInitializationEnvironment: production
secretProviders:
  file:
    root: {}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 1
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: {}
    runtime: {}
package:
  root: {}
  trustAnchorPath: {}
  compilerSourceRevision: {SOURCE_REVISION}
  activeRevision: {}
  activeSequence: {}
authentication:
  oidc:
    issuer: {}
    audience: urn:registry-server:test
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 200
      outageToleranceSeconds: 0
  authorityClaims:
    principal: principal
audit:
  hashKeyRef: {hash_key_ref}
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
operationalTimeouts:
  httpRequestMilliseconds: 5000
  shutdownGraceMilliseconds: 1000
  recordLockMilliseconds: 1000
  migrationLockMilliseconds: 1000
  migrationStatementMilliseconds: 1000
"#,
                self.secret_root.display(),
                migration_role.as_str(),
                runtime_role.as_str(),
                package.root.display(),
                package.anchor.display(),
                package.revision,
                package.sequence,
                issuer
            ),
        )
        .expect("runtime config writes");
        fs::write(self.secret_root.join("database-url"), "unused")
            .expect("unused DB URL secret writes");
        path
    }
}

impl Drop for StartupFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct PackageFixture {
    root: PathBuf,
    anchor: PathBuf,
    revision: String,
    sequence: u64,
}

impl PackageFixture {
    fn build(parent: &Path, schema_fingerprint: String, signing: &PrivateJwk) -> Self {
        Self::build_version(parent, schema_fingerprint, signing, 1, None, false)
    }

    fn build_successor(
        parent: &Path,
        schema_fingerprint: String,
        signing: &PrivateJwk,
        prior_revision: &str,
    ) -> Self {
        Self::build_version(
            parent,
            schema_fingerprint,
            signing,
            2,
            Some(prior_revision),
            true,
        )
    }

    fn build_version(
        parent: &Path,
        schema_fingerprint: String,
        signing: &PrivateJwk,
        sequence: u64,
        prior_revision: Option<&str>,
        successor: bool,
    ) -> Self {
        let ordinal = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = parent.join(format!("package-{ordinal}"));
        let module_source = module_bytes(successor);
        let module = parse_module_yaml(&module_source).expect("fixture module parses");
        let project_source = project_bytes(sequence, &module_digest(&module));
        let key_id = signing.public().kid.expect("generated key has kid");
        let migration_plan = if successor {
            let prior_module_bytes = module_bytes(false);
            let prior_module =
                parse_module_yaml(&prior_module_bytes).expect("prior fixture module parses");
            let prior_project_bytes = project_bytes(1, &module_digest(&prior_module));
            let prior_project =
                parse_project_yaml(&prior_project_bytes).expect("prior fixture project parses");
            let prior_registry =
                compile_project(&prior_project, &[prior_module], CompileProfile::Production)
                    .expect("prior fixture Registry compiles");
            PackageMigrationPlanInput::Successor {
                prior_registry: Box::new(prior_registry),
            }
        } else {
            PackageMigrationPlanInput::InitialCompiledDdl
        };
        let prepared = prepare_package(PackageBuildRequest {
            environment: "production".to_owned(),
            instance_id: INSTANCE.to_owned(),
            database_id: DATABASE.to_owned(),
            sequence,
            prior_revision: prior_revision.map(str::to_owned),
            compiler_source_revision: SOURCE_REVISION.to_owned(),
            schema_fingerprint,
            signature_policy: SignaturePolicy {
                threshold: 1,
                key_ids: vec![key_id.clone()],
            },
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes: project_source,
            },
            modules: vec![PackageModuleSource {
                id: "core".to_owned(),
                path: "source/modules/core/module.yaml".to_owned(),
                bytes: module_source,
            }],
            fixture_journeys: PackageSourceFile {
                path: "tests/journeys.yaml".to_owned(),
                bytes: FIXTURE_JOURNEYS.to_vec(),
            },
            migration_plan,
        })
        .expect("fixture package prepares");
        let signature =
            sign(prepared.canonical_signed_bytes(), signing).expect("fixture package signs");
        prepared
            .publish_to_directory(
                &root,
                vec![PackageSignature {
                    key_id: key_id.clone(),
                    signature_hex: hex(&signature),
                }],
            )
            .expect("fixture package publishes");
        let anchor = parent.join(format!("trust-anchor-{ordinal}.json"));
        write_json(
            &anchor,
            &PackageTrustAnchor {
                api_version: TRUST_ANCHOR_API_VERSION.to_owned(),
                environment: "production".to_owned(),
                instance_id: INSTANCE.to_owned(),
                database_id: DATABASE.to_owned(),
                threshold: 1,
                keys: vec![TrustAnchorKey {
                    key_id,
                    jwk: serde_json::to_value(signing.public()).expect("public JWK serializes"),
                }],
            },
        );
        Self {
            root,
            anchor,
            revision: prepared.package_revision().to_owned(),
            sequence,
        }
    }

    fn context<'a>(&'a self, intent: PackageIntent<'a>) -> PackageLoadContext<'a> {
        PackageLoadContext {
            environment: "production",
            instance_id: INSTANCE,
            database_id: DATABASE,
            database_initialization_environment: "production",
            compiler_source_revision: SOURCE_REVISION,
            trust_anchor: Some(&self.anchor),
            intent,
        }
    }
}

fn project_bytes(sequence: u64, module_digest: &str) -> Vec<u8> {
    let project = format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en"}},"package":{{"environment":"production","instanceId":"{INSTANCE}","sequence":{sequence},"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"name":"Package Test Publisher"}}}},"dataset":{{"title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    );
    parse_project_yaml(project.as_bytes()).expect("project fixture parses");
    project.into_bytes()
}

fn module_bytes(successor: bool) -> Vec<u8> {
    let second = if successor {
        r#",{"id":"second-record","route":"second-records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get"],"readableFields":["code"]}]}"#
    } else {
        ""
    };
    format!(
        r#"{{"id":"core","version":"1","entities":[{{"id":"neutral-record","route":"neutral-records","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":8,"classification":"internal"}}],"accessProfiles":[{{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"]}}]}}{second}]}}"#
    )
    .into_bytes()
}

fn write_json(path: &Path, value: &impl Serialize) {
    let bytes = canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes");
    fs::write(path, bytes).expect("fixture JSON writes");
}

fn fingerprint(byte: u8) -> String {
    format!("sha256:{}", format!("{byte:02x}").repeat(32))
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String succeeds");
    }
    result
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
