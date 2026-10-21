// SPDX-License-Identifier: Apache-2.0

//! Shared setup for the PostgreSQL suites: one isolated schema per test,
//! a development runtime document whose secrets are owner-only files, and
//! the starter package.
//!
//! The database is named by `DOCUMENTS_TEST_DATABASE_URL`. A test binary
//! that passes because its database URL is absent is not database
//! verification, so the variable is required: without it every test fails
//! on the spot.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use registry_documents::package::{package_limits, PACKAGE_COMMAND, PROJECT_FILE};
use registry_documents::store::PostgresStore;
use registry_platform_config::write_package;
use uuid::Uuid;

pub const STARTER_PROJECT: &str =
    include_str!("../../../../products/documents/examples/starter/documents.yaml");

pub const DATABASE_STORAGE: &str = "storage:\n  type: database\n";
pub const DISABLED_VERIFIER: &str = "contentVerification:\n  type: disabled\n";

pub fn database_url() -> String {
    std::env::var("DOCUMENTS_TEST_DATABASE_URL")
        .expect("DOCUMENTS_TEST_DATABASE_URL names a disposable PostgreSQL test server")
}

/// One deployment under test: its directory, runtime document, and the
/// isolated schema its database URL resolves into.
pub struct Deployment {
    pub directory: tempfile::TempDir,
    pub runtime: PathBuf,
    pub schema: String,
    pub admin: tokio_postgres::Client,
    secrets: PathBuf,
    scoped_url: String,
    storage: String,
    verifier: String,
}

impl Deployment {
    /// A deployment over a fresh schema, with `storage` and `verifier` as
    /// the runtime document's storage and content verification blocks.
    pub async fn new(storage: &str, verifier: &str) -> Self {
        Self::with_url(storage, verifier, None).await
    }

    /// As [`Deployment::new`], with the runtime credential replaced by
    /// `runtime_url` when one is given.
    pub async fn with_url(storage: &str, verifier: &str, runtime_url: Option<&str>) -> Self {
        let base = database_url();
        let schema = format!("documents_{}", Uuid::new_v4().simple());
        let separator = if base.contains('?') { '&' } else { '?' };
        let scoped_url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let (admin, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
            .await
            .expect("connect the documents test database");
        tokio::spawn(async move { connection.await.expect("the documents admin connection") });
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .expect("an isolated documents schema");

        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let secrets = directory.path().join("secrets");
        std::fs::create_dir(&secrets).unwrap();
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut deployment = Self {
            runtime: directory.path().join("runtime.yaml"),
            directory,
            schema,
            admin,
            secrets,
            scoped_url: scoped_url.clone(),
            storage: storage.to_owned(),
            verifier: verifier.to_owned(),
        };
        deployment.secret("runtime-database-url", runtime_url.unwrap_or(&scoped_url));
        deployment.secret("migration-database-url", &scoped_url);
        deployment.secret(
            "documents-audit-key",
            "documents-test-audit-key-not-a-secret",
        );
        deployment.write_package();
        deployment.write_runtime();
        deployment
    }

    /// Write one owner-only secret file.
    pub fn secret(&mut self, name: &str, value: &str) {
        let path = self.secrets.join(name);
        std::fs::write(&path, value).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    pub fn audit_path(&self) -> PathBuf {
        self.directory.path().join("audit.ndjson")
    }

    fn write_package(&self) {
        let files =
            BTreeMap::from([(PROJECT_FILE.to_owned(), STARTER_PROJECT.as_bytes().to_vec())]);
        write_package(
            &self.directory.path().join("package"),
            &files,
            None,
            &package_limits(),
            PACKAGE_COMMAND,
        )
        .unwrap();
    }

    /// Rewrite the runtime document with other storage and verifier
    /// blocks, as an operator does between restarts.
    pub fn reconfigure(&mut self, storage: &str, verifier: &str) {
        self.storage = storage.to_owned();
        self.verifier = verifier.to_owned();
        self.write_runtime();
    }

    fn write_runtime(&self) {
        let document = format!(
            "\
apiVersion: id.registrystack.org/formats/documents/runtime/v1alpha1
kind: DocumentsRuntimeConfig
identity:
  databaseId: registry-documents-test
package:
  root: {package}
listener:
  bind: 127.0.0.1:0
  tlsTermination: development-loopback
  networkExposure: private-address
secretProviders:
  file:
    root: {secrets}
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
  testOnlyPlaintext: true
authentication:
  oidc:
    issuer: https://identity.example.test/realms/registry
    audience: urn:example:documents
    allowedClients: [documents-test]
audit:
  destination: file
  path: {audit}
  hashKeyRef: secret:file/documents-audit-key
{storage}{verifier}cleanup:
  erasure: active
",
            package = self.directory.path().join("package").display(),
            secrets = self.secrets.display(),
            audit = self.audit_path().display(),
            storage = self.storage,
            verifier = self.verifier,
        );
        std::fs::write(&self.runtime, document).unwrap();
    }

    /// Apply the schema over the migration credential.
    pub async fn migrate(&self) {
        let config = registry_documents::config::RuntimeConfig::load(&self.runtime)
            .expect("the test runtime document loads");
        let secrets = config.secret_resolver().unwrap();
        PostgresStore::connect_migration(&config.database, &secrets)
            .unwrap()
            .migrate()
            .await
            .expect("the schema applies");
    }

    /// The audit entries written so far, one JSON value per line.
    pub fn audit_entries(&self) -> Vec<serde_json::Value> {
        match std::fs::read_to_string(self.audit_path()) {
            Ok(text) => text
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("the audit journal is unreadable: {error}"),
        }
    }

    pub fn path(&self) -> &Path {
        self.directory.path()
    }
}
