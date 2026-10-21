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
    project: String,
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
        Self::build(storage, verifier, runtime_url, STARTER_PROJECT).await
    }

    /// As [`Deployment::new`], with `project` as the packaged project.
    pub async fn with_project(storage: &str, verifier: &str, project: &str) -> Self {
        Self::build(storage, verifier, None, project).await
    }

    async fn build(
        storage: &str,
        verifier: &str,
        runtime_url: Option<&str>,
        project: &str,
    ) -> Self {
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
            project: project.to_owned(),
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
        let files = BTreeMap::from([(PROJECT_FILE.to_owned(), self.project.as_bytes().to_vec())]);
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

/// The issuer every synthetic actor carries.
pub const TEST_ISSUER: &str = "https://identity.example.test/realms/registry";

/// The header a test names its caller in. A request without it has no
/// actor.
pub const TEST_SUBJECT_HEADER: &str = "x-test-subject";

/// A synthetic actor source: the caller is the subject the test header
/// names, acting under the custodian application's profile.
#[derive(Debug, Default)]
pub struct TestActors;

impl registry_documents::actor::ActorSource for TestActors {
    fn actor(&self, headers: &axum::http::HeaderMap) -> Option<registry_documents::actor::Actor> {
        let subject = headers.get(TEST_SUBJECT_HEADER)?.to_str().ok()?;
        Some(registry_documents::actor::Actor {
            issuer: TEST_ISSUER.to_owned(),
            subject: subject.to_owned(),
            kind: registry_documents::actor::ActorKind::Service,
            client_id: "civil-registry-app".to_owned(),
            access_profile_id: "custodian-app".to_owned(),
            issuing_institution: "civil-registry".to_owned(),
        })
    }
}

/// What a [`FakeVerifier`] answers.
pub const APPROVE: u8 = 0;
pub const REJECT: u8 = 1;
pub const UNAVAILABLE: u8 = 2;

/// A content verifier under test control: it approves, rejects, or does
/// not answer, under the binding it was made with.
#[derive(Debug)]
pub struct FakeVerifier {
    binding: String,
    mode: std::sync::atomic::AtomicU8,
    pub calls: std::sync::atomic::AtomicUsize,
}

impl FakeVerifier {
    pub fn new(binding: &str, mode: u8) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            binding: binding.to_owned(),
            mode: std::sync::atomic::AtomicU8::new(mode),
            calls: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    pub fn answer(&self, mode: u8) {
        self.mode.store(mode, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl registry_documents::verification::VerdictSource for FakeVerifier {
    fn binding_digest(&self) -> &str {
        &self.binding
    }

    async fn verdict(
        &self,
        _sha256: &str,
        _media_type: &str,
        _bytes: Vec<u8>,
    ) -> Result<registry_platform_objectstore::Verdict, registry_platform_objectstore::VerifierError>
    {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match self.mode.load(std::sync::atomic::Ordering::SeqCst) {
            APPROVE => Ok(registry_platform_objectstore::Verdict::Approved),
            REJECT => Ok(registry_platform_objectstore::Verdict::Rejected),
            _ => Err(registry_platform_objectstore::VerifierError::Unavailable),
        }
    }
}

/// One answered request: its status, headers, and body.
#[derive(Debug)]
pub struct Answer {
    pub status: u16,
    pub headers: axum::http::HeaderMap,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("a JSON body")
    }

    /// Assert this is exactly the problem `code` names.
    pub fn assert_problem(&self, code: registry_documents_core::ProblemCode) {
        assert_eq!(
            self.status,
            code.http_status(),
            "{code:?}: {}",
            String::from_utf8_lossy(&self.body)
        );
        assert_eq!(self.headers["content-type"], "application/problem+json");
        assert_eq!(self.json()["code"], code.code());
    }
}

/// The document router of a prepared runtime, acting through
/// [`TestActors`].
#[derive(Clone)]
pub struct Api {
    router: axum::Router,
}

impl Api {
    pub fn new(prepared: &registry_documents::runtime::Prepared) -> Self {
        Self {
            router: registry_documents::http::document_router(
                prepared.service(),
                std::sync::Arc::new(TestActors),
            ),
        }
    }

    pub async fn call(&self, request: axum::http::Request<axum::body::Body>) -> Answer {
        use tower::ServiceExt as _;
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        Answer {
            status,
            headers,
            body,
        }
    }

    /// Reserve a document for `custodian` as `subject`.
    pub async fn reserve(
        &self,
        subject: &str,
        policy: &str,
        custodian: &str,
        content: &[u8],
        media_type: &str,
    ) -> Answer {
        self.reserve_declared(
            subject,
            policy,
            custodian,
            &sha256(content),
            content.len() as u64,
            media_type,
        )
        .await
    }

    pub async fn reserve_declared(
        &self,
        subject: &str,
        policy: &str,
        custodian: &str,
        digest: &str,
        length: u64,
        media_type: &str,
    ) -> Answer {
        let body = serde_json::json!({
            "policyId": policy,
            "custodian": {"subject": custodian},
            "expectedDigest": digest,
            "length": length,
            "mediaType": media_type,
        });
        self.call(
            axum::http::Request::post("/documents")
                .header(TEST_SUBJECT_HEADER, subject)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    /// Send `body` as the content of the upload at `path`.
    pub async fn put(
        &self,
        subject: &str,
        path: &str,
        media_type: &str,
        body: axum::body::Body,
    ) -> Answer {
        self.call(
            axum::http::Request::put(path)
                .header(TEST_SUBJECT_HEADER, subject)
                .header("content-type", media_type)
                .body(body)
                .unwrap(),
        )
        .await
    }

    pub async fn read(&self, subject: &str, document: &str) -> Answer {
        self.call(
            axum::http::Request::get(format!("/documents/{document}"))
                .header(TEST_SUBJECT_HEADER, subject)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
    }

    pub async fn download(&self, subject: &str, document: &str, version: &str) -> Answer {
        self.call(
            axum::http::Request::get(format!("/documents/{document}/versions/{version}/content"))
                .header(TEST_SUBJECT_HEADER, subject)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
    }
}

/// The `sha256:<hex>` digest of `bytes`.
pub fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

/// A small synthetic PDF body of `length` bytes.
pub fn pdf(length: usize, seed: u8) -> Vec<u8> {
    let mut bytes = b"%PDF-1.7\n".to_vec();
    bytes.extend(
        (0..length.saturating_sub(bytes.len()))
            .map(|index| seed.wrapping_add(u8::try_from(index % 251).unwrap())),
    );
    bytes.truncate(length);
    bytes
}

/// The reservation `answer` carries: the document id, version id, and
/// upload path.
pub fn reservation(answer: &Answer) -> (String, String, String) {
    assert_eq!(
        answer.status,
        201,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let view = answer.json();
    (
        view["document"]["id"].as_str().unwrap().to_owned(),
        view["document"]["version"]["id"]
            .as_str()
            .unwrap()
            .to_owned(),
        view["uploadPath"].as_str().unwrap().to_owned(),
    )
}

impl Deployment {
    /// One value from the isolated schema.
    pub async fn scalar<T>(&self, sql: &str) -> T
    where
        T: for<'a> tokio_postgres::types::FromSql<'a>,
    {
        self.admin
            .batch_execute(&format!("SET search_path TO {}", self.schema))
            .await
            .unwrap();
        self.admin.query_one(sql, &[]).await.unwrap().get(0)
    }

    /// Run `sql` in the isolated schema.
    pub async fn execute(&self, sql: &str) {
        self.admin
            .batch_execute(&format!("SET search_path TO {}; {sql}", self.schema))
            .await
            .unwrap();
    }
}
