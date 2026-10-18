// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

use std::{env, net::TcpListener, str::FromStr as _, time::Duration};

use registry_breg::postgres::{ConnectionConfig, DatabaseConnectionCause, PoolBounds, RuntimePool};
use tokio_postgres::{Config, NoTls};

fn database_config() -> Config {
    let url = env::var("BREG_TEST_DATABASE_URL")
        .expect("BREG_TEST_DATABASE_URL is required for database diagnostic tests");
    Config::from_str(&url).expect("BREG_TEST_DATABASE_URL must be a valid PostgreSQL URL")
}

fn bounds(max_size: usize) -> PoolBounds {
    PoolBounds::new(
        max_size,
        Duration::from_millis(100),
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .expect("diagnostic pool bounds are valid")
}

fn plaintext_pool(config: Config, max_size: usize) -> RuntimePool {
    ConnectionConfig::from_test_config(config, bounds(max_size))
        .expect("test connection configuration is valid")
        .build_pool()
        .expect("test connection pool builds")
}

#[tokio::test]
async fn startup_classifies_wrong_role_and_password_as_authentication() {
    let mut wrong_role = database_config();
    wrong_role.user("diagnostic-role-does-not-exist");
    let role_cause = plaintext_pool(wrong_role, 1)
        .startup_connection_cause_for_test()
        .await;
    assert_eq!(role_cause, Err(DatabaseConnectionCause::Authentication));

    let mut wrong_password = database_config();
    wrong_password.password("diagnostic-canary-password-is-wrong");
    let password_cause = plaintext_pool(wrong_password, 1)
        .startup_connection_cause_for_test()
        .await;
    assert_eq!(password_cause, Err(DatabaseConnectionCause::Authentication));
}

#[tokio::test]
async fn startup_classifies_a_missing_database() {
    let mut missing_database = database_config();
    missing_database.dbname("diagnostic_database_does_not_exist");
    let cause = plaintext_pool(missing_database, 1)
        .startup_connection_cause_for_test()
        .await;
    assert_eq!(cause, Err(DatabaseConnectionCause::DatabaseMissing));
}

#[tokio::test]
async fn startup_classifies_an_unreachable_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral listener binds");
    let port = listener
        .local_addr()
        .expect("listener has an address")
        .port();
    drop(listener);

    let config = Config::from_str(&format!(
        "postgresql://diagnostic-canary-user:diagnostic-canary-password@127.0.0.1:{port}/diagnostic-database"
    ))
    .expect("unreachable test configuration parses");
    let cause = plaintext_pool(config, 1)
        .startup_connection_cause_for_test()
        .await;
    assert_eq!(cause, Err(DatabaseConnectionCause::Unreachable));
}

#[tokio::test]
async fn startup_classifies_pool_wait_timeout() {
    let pool = plaintext_pool(database_config(), 1);
    let held = pool
        .get_for_test()
        .await
        .expect("the only pool connection opens");
    let cause = pool.startup_connection_cause_for_test().await;
    assert_eq!(cause, Err(DatabaseConnectionCause::Timeout));
    drop(held);
}

#[tokio::test]
async fn startup_classifies_server_capacity_without_disclosing_connection_values() {
    let (admin, admin_connection) = database_config()
        .connect(NoTls)
        .await
        .expect("diagnostic administrator connects");
    let admin_task = tokio::spawn(async move { admin_connection.await });
    let role = format!("diagnostic_capacity_canary_{}", std::process::id());
    admin
        .batch_execute(&format!(
            "DROP ROLE IF EXISTS {role}; CREATE ROLE {role} LOGIN PASSWORD 'diagnostic-canary-capacity-password' CONNECTION LIMIT 1"
        ))
        .await
        .expect("capacity test role is created");

    let mut limited = database_config();
    limited.user(&role);
    limited.password("diagnostic-canary-capacity-password");
    let (held, held_connection) = limited
        .connect(NoTls)
        .await
        .expect("the role's one connection opens");
    let held_task = tokio::spawn(async move { held_connection.await });

    let pool = plaintext_pool(limited, 1);
    let cause = pool
        .startup_connection_cause_for_test()
        .await
        .expect_err("the role's connection limit refuses another connection");

    drop(held);
    held_task
        .await
        .expect("held connection task joins")
        .expect("held connection closes cleanly");
    let recovered = pool
        .get_for_test()
        .await
        .expect("freeing the role's connection restores pool acquisition");
    drop(recovered);
    admin
        .batch_execute(&format!("DROP ROLE {role}"))
        .await
        .expect("capacity test role is removed");
    drop(admin);
    admin_task
        .await
        .expect("administrator connection task joins")
        .expect("administrator connection closes cleanly");

    assert_eq!(cause.code(), "startup.database.capacity-exhausted");
    assert_eq!(cause.diagnostic_path(), "database");
    assert_eq!(
        cause.message(),
        "the database connection capacity is exhausted; free connections or increase PostgreSQL connection capacity"
    );
    for secret in [
        role.as_str(),
        "diagnostic-canary-capacity-password",
        "too many connections",
    ] {
        assert!(!cause.message().contains(secret), "{}", cause.message());
    }
}

#[tokio::test]
async fn startup_classifies_plaintext_server_tls_refusal() {
    let tls = ConnectionConfig::require_tls_config(database_config(), bounds(1))
        .expect("TLS-required connection configuration is valid")
        .build_pool()
        .expect("TLS-required connection pool builds");
    let cause = tls.startup_connection_cause_for_test().await;
    assert_eq!(cause, Err(DatabaseConnectionCause::Tls));
}
