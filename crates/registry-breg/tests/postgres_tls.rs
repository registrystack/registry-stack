// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-tls-test")]

use std::{env, fs, str::FromStr, time::Duration};

use registry_breg::postgres::{ConnectionConfig, PoolBounds};
use tokio::{net::TcpStream, time::timeout};
use tokio_postgres::{config::Host, Config};

fn required_env(name: &str) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| panic!("{name} must be set for the real PostgreSQL TLS test"))
}

fn read_required_der(path_env: &str) -> Vec<u8> {
    let path = required_env(path_env);
    fs::read(&path).unwrap_or_else(|error| panic!("failed to read {path_env} at {path}: {error}"))
}

fn tcp_connection_identity(url: &str) -> (String, u16, Option<String>, Option<String>) {
    let config = Config::from_str(url).expect("TLS test database URL must parse");
    let hosts = config.get_hosts();
    assert_eq!(hosts.len(), 1, "TLS test URL must name exactly one host");
    let host = match &hosts[0] {
        Host::Tcp(host) => host.clone(),
        #[cfg(unix)]
        Host::Unix(_) => panic!("TLS test URL must use a TCP host"),
    };
    let ports = config.get_ports();
    assert!(ports.len() <= 1, "TLS test URL must name at most one port");
    let port = ports.first().copied().unwrap_or(5432);
    (
        host,
        port,
        config.get_user().map(str::to_owned),
        config.get_dbname().map(str::to_owned),
    )
}

#[tokio::test]
async fn custom_ca_requires_a_trusted_tls_server() {
    let database_url = required_env("BREG_TEST_TLS_DATABASE_URL");
    let hostname_mismatch_url = required_env("BREG_TEST_TLS_HOSTNAME_MISMATCH_DATABASE_URL");
    let trusted_ca = read_required_der("BREG_TEST_TLS_CA_DER_PATH");
    let wrong_ca = read_required_der("BREG_TEST_TLS_WRONG_CA_DER_PATH");
    assert_ne!(
        trusted_ca, wrong_ca,
        "the wrong-root fixture must differ from the trusted CA"
    );

    let bounds = PoolBounds::new(
        1,
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .expect("TLS test pool bounds are valid");
    let trusted = ConnectionConfig::require_tls_with_custom_ca(&database_url, &trusted_ca, bounds)
        .expect("trusted CA DER and database URL must parse");
    assert_eq!(
        format!("{trusted:?}"),
        format!("ConnectionConfig {{ tls_policy: RequireCustomCa, pool_bounds: {bounds:?}, .. }}"),
        "Debug must not disclose the URL or CA certificate"
    );

    let trusted_pool = trusted.build_pool().expect("TLS pool must build");
    trusted_pool
        .startup_probe()
        .await
        .expect("trusted custom CA must establish a PostgreSQL connection");
    let client = trusted_pool
        .get_for_test()
        .await
        .expect("trusted TLS connection must be reusable");
    let ssl: bool = client
        .query_one(
            "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
            &[],
        )
        .await
        .expect("PostgreSQL must report the transport state")
        .get(0);
    assert!(ssl, "the accepted PostgreSQL connection must use TLS");
    drop(client);
    drop(trusted_pool);

    let (trusted_host, trusted_port, trusted_user, trusted_database) =
        tcp_connection_identity(&database_url);
    let (mismatch_host, mismatch_port, mismatch_user, mismatch_database) =
        tcp_connection_identity(&hostname_mismatch_url);
    assert_ne!(
        trusted_host, mismatch_host,
        "the hostname-mismatch URL must use a different host"
    );
    assert_eq!(
        (trusted_port, trusted_user, trusted_database),
        (mismatch_port, mismatch_user, mismatch_database),
        "the hostname-mismatch URL may differ only in its host"
    );
    let mismatch_tcp = timeout(
        Duration::from_secs(5),
        TcpStream::connect((mismatch_host.as_str(), mismatch_port)),
    )
    .await
    .expect("hostname-mismatch TCP reachability probe must not time out")
    .expect("hostname-mismatch URL must reach the PostgreSQL listener");
    drop(mismatch_tcp);

    let hostname_mismatch =
        ConnectionConfig::require_tls_with_custom_ca(&hostname_mismatch_url, &trusted_ca, bounds)
            .expect("trusted CA and hostname-mismatch URL must parse");
    let hostname_mismatch_pool = hostname_mismatch
        .build_pool()
        .expect("hostname-mismatch pool must build");
    assert!(
        hostname_mismatch_pool.startup_probe().await.is_err(),
        "a trusted chain with a hostname absent from the certificate SAN must be refused"
    );

    let untrusted = ConnectionConfig::require_tls_with_custom_ca(&database_url, &wrong_ca, bounds)
        .expect("the wrong-root fixture must still be valid DER");
    let untrusted_pool = untrusted.build_pool().expect("wrong-root pool must build");
    assert!(
        untrusted_pool.startup_probe().await.is_err(),
        "a valid but untrusted CA must not establish a PostgreSQL connection"
    );
}
