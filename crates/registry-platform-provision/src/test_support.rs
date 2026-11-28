// SPDX-License-Identifier: Apache-2.0
//! Helpers for the PostgreSQL tests of the products that provision with this
//! crate. They panic with a message that names the variable or the failure,
//! never the URL or the password.

use tokio_postgres::Client;

use crate::admin_config;

/// Reads `PROVISION_TEST_DATABASE_URL` and the CA PEM file named by
/// `PROVISION_TEST_DATABASE_CA`. A missing variable or unreadable file fails
/// the test: a skipped database test is not database verification.
pub fn provision_test_env() -> (String, Vec<u8>) {
    let url = std::env::var("PROVISION_TEST_DATABASE_URL")
        .expect("PROVISION_TEST_DATABASE_URL names a disposable PostgreSQL superuser URL");
    let ca_path = std::env::var("PROVISION_TEST_DATABASE_CA")
        .expect("PROVISION_TEST_DATABASE_CA names the PEM CA of the test server");
    let ca = std::fs::read(&ca_path).unwrap_or_else(|error| {
        panic!("cannot read the file PROVISION_TEST_DATABASE_CA names: {error}")
    });
    (url, ca)
}

/// Opens a session over TLS verified against `ca_pem`, with the endpoint and
/// credentials of `url` (the same rules `provision` applies to an
/// administrator URL). `database` replaces the one the URL names. The
/// connection task runs on the current runtime.
pub async fn connect_verified(url: &str, ca_pem: &[u8], database: Option<&str>) -> Client {
    let config = admin_config(url, Some(ca_pem))
        .unwrap_or_else(|error| panic!("the test PostgreSQL URL or CA is refused: {error}"));
    config
        .connect_detached(database)
        .await
        .unwrap_or_else(|error| panic!("cannot open a verified-TLS test session: {error}"))
}
