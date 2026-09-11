// SPDX-License-Identifier: Apache-2.0

//! A startup secret failure names the reference and the rule it broke.
//!
//! `migrate` and the audit journal resolve operator secrets before anything
//! else runs, so their failures are the first thing an operator reads. Each
//! assertion below names one flattened path and proves the message carries the
//! failing reference and its reason without carrying the resolved bytes.

use registry_casework::{DatabaseConfig, PostgresStore};
use registry_platform_config::{SecretProvider, SecretResolver};

const DATABASE_URL: &[u8] = b"postgresql://casework@localhost/casework";

fn database(reference: &str) -> DatabaseConfig {
    DatabaseConfig {
        runtime_url_ref: reference.to_owned(),
        migration_url_ref: reference.to_owned(),
        trusted_root_certificate_ref: None,
        test_only_plaintext: false,
    }
}

#[test]
fn a_missing_database_reference_names_the_reference_and_says_it_is_missing() {
    let root = tempfile::tempdir().expect("temporary secret root");
    let secrets = SecretResolver::new([SecretProvider::File], root.path()).expect("resolver");

    let error =
        PostgresStore::connect_migration(&database("secret:file/casework-database-url"), &secrets)
            .expect_err("an absent secret file cannot resolve");

    let message = error.to_string();
    assert!(
        message.contains("secret:file/casework-database-url"),
        "the failure does not name the reference: {message}"
    );
    assert!(
        message.contains("no readable"),
        "the failure does not say the secret is missing: {message}"
    );
}

#[cfg(unix)]
mod unix {
    use super::*;

    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    fn write_secret(root: &Path, name: &str, value: &[u8], mode: u32) {
        let path = root.join(name);
        fs::write(&path, value).expect("write secret");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
    }

    #[test]
    fn a_group_readable_database_reference_names_the_reference_and_the_mode_rule() {
        let root = tempfile::tempdir().expect("temporary secret root");
        write_secret(root.path(), "casework-database-url", DATABASE_URL, 0o644);
        let secrets = SecretResolver::new([SecretProvider::File], root.path()).expect("resolver");

        let error = PostgresStore::connect_migration(
            &database("secret:file/casework-database-url"),
            &secrets,
        )
        .expect_err("a group-readable secret file is refused");

        let message = error.to_string();
        assert!(
            message.contains("secret:file/casework-database-url"),
            "the failure does not name the reference: {message}"
        );
        assert!(
            message.contains("0400 or 0600"),
            "the failure does not name the mode rule: {message}"
        );
        assert!(
            !message.contains("postgresql://"),
            "the failure echoes the resolved secret: {message}"
        );
    }

    #[test]
    fn a_group_readable_trusted_root_reference_names_that_reference() {
        let root = tempfile::tempdir().expect("temporary secret root");
        write_secret(root.path(), "casework-database-url", DATABASE_URL, 0o600);
        write_secret(
            root.path(),
            "database-root.pem",
            b"-----BEGIN CERTIFICATE-----",
            0o644,
        );
        let secrets = SecretResolver::new([SecretProvider::File], root.path()).expect("resolver");
        let mut config = database("secret:file/casework-database-url");
        config.trusted_root_certificate_ref = Some("secret:file/database-root.pem".to_owned());

        let error = PostgresStore::connect_runtime(&config, &secrets)
            .expect_err("a group-readable certificate file is refused");

        let message = error.to_string();
        assert!(
            message.contains("secret:file/database-root.pem"),
            "the failure does not name the certificate reference: {message}"
        );
        assert!(
            message.contains("0400 or 0600"),
            "the failure does not name the mode rule: {message}"
        );
    }
}
