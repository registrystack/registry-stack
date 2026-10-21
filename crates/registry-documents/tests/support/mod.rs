// SPDX-License-Identifier: Apache-2.0

//! Shared setup for the PostgreSQL suites: one isolated schema per test,
//! a development runtime document whose secrets are owner-only files, the
//! starter package, and real ES256 access tokens signed by a test issuer
//! whose public key set the runtime reads as a static secret.
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
use registry_platform_config::write_package;
use uuid::Uuid;

pub const STARTER_PROJECT: &str =
    include_str!("../../../../products/documents/examples/starter/documents.yaml");

pub const DATABASE_STORAGE: &str = "storage:\n  type: database\n";
pub const DISABLED_VERIFIER: &str = "contentVerification:\n  type: disabled\n";

/// Where the starter hooks deliver until a suite binds a receiver: a
/// loopback port nothing listens on, so a delivery attempt fails rather
/// than reaching anything.
pub const UNREACHABLE_HOOKS_URL: &str = "http://127.0.0.1:9/document-events";

/// The test-only HMAC key the hook destination signs with.
pub const HOOK_KEY: &str = "documents-test-hook-key-not-a-secret-0123456789";

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
    erasure: &'static str,
    extra: String,
    hooks_url: String,
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
            erasure: "active",
            extra: String::new(),
            hooks_url: UNREACHABLE_HOOKS_URL.to_owned(),
        };
        deployment.secret("runtime-database-url", runtime_url.unwrap_or(&scoped_url));
        deployment.secret("migration-database-url", &scoped_url);
        deployment.secret(
            "documents-audit-key",
            "documents-test-audit-key-not-a-secret",
        );
        deployment.secret("jwks.json", &issuer().jwks);
        deployment.secret("hook-key", HOOK_KEY);
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

    /// Set `cleanup.erasure` to `mode`, `active` or `paused`.
    pub fn set_erasure(&mut self, mode: &'static str) {
        self.erasure = mode;
        self.write_runtime();
    }

    /// Bind the `custodian-events` hook destination every starter hook
    /// names to `url`, as an operator does between restarts.
    pub fn bind_hooks(&mut self, url: &str) {
        self.hooks_url = url.to_owned();
        self.write_runtime();
    }

    /// Append `block`, top-level runtime keys, to the runtime document.
    pub fn configure(&mut self, block: &str) {
        self.extra = block.to_owned();
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
    scopeClaim: scope
    allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal, partner-service]
    jwksSource:
      type: static
      documentRef: secret:file/jwks.json
audit:
  destination: file
  path: {audit}
  hashKeyRef: secret:file/documents-audit-key
{storage}{verifier}cleanup:
  erasure: {erasure}
destinations:
  hooks:
    custodian-events:
      url: {hooks_url}
      hmacSha256KeyRef: secret:file/hook-key
      attemptTimeoutMilliseconds: 1000
      maximumAttempts: 2
{extra}",
            package = self.directory.path().join("package").display(),
            secrets = self.secrets.display(),
            audit = self.audit_path().display(),
            storage = self.storage,
            verifier = self.verifier,
            erasure = self.erasure,
            extra = self.extra,
            hooks_url = self.hooks_url,
        );
        std::fs::write(&self.runtime, document).unwrap();
    }

    /// Apply the schema and activate the package over the migration
    /// credential, as `documentsctl apply` does.
    pub async fn migrate(&self) {
        let config = registry_documents::config::RuntimeConfig::load(&self.runtime)
            .expect("the test runtime document loads");
        registry_documents::runtime::apply_activation(
            &config,
            &registry_documents::activation::ApplyRequest::default(),
        )
        .await
        .expect("the package applies");
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

/// The issuer every test token names.
pub const TEST_ISSUER: &str = "https://identity.example.test/realms/registry";
pub const TEST_AUDIENCE: &str = "urn:example:documents";
const TEST_KEY_ID: &str = "documents-test-1";

/// One caller under test: the subject a token names and the client,
/// scope, and actor kind that resolve it to one starter access profile.
#[derive(Clone, Copy, Debug)]
pub struct Principal {
    pub subject: &'static str,
    pub client: &'static str,
    pub scope: &'static str,
    pub kind: &'static str,
}

/// The owning system, under the `custodian-app` profile.
pub const APP: Principal = Principal {
    subject: "custodian-app",
    client: "civil-registry-app",
    scope: "documents:custody",
    kind: "service",
};
/// A second service under the same profile, at another subject.
pub const OTHER_APP: Principal = Principal {
    subject: "other-app",
    ..APP
};
/// The person a document concerns, under the `citizen` profile.
pub const CITIZEN: Principal = Principal {
    subject: "citizen-1",
    client: "citizen-portal",
    scope: "documents:own",
    kind: "human",
};
pub const OTHER_CITIZEN: Principal = Principal {
    subject: "citizen-2",
    ..CITIZEN
};
/// A named recipient under the `reader` profile.
pub const READER: Principal = Principal {
    subject: "reader-1",
    client: "partner-portal",
    scope: "documents:read",
    kind: "human",
};
/// A recipient profile holder no grant names.
pub const STRANGER: Principal = Principal {
    subject: "someone-else",
    ..READER
};
/// A named recipient under the `staff` profile.
pub const STAFF: Principal = Principal {
    subject: "staff-1",
    client: "case-portal",
    scope: "documents:read",
    kind: "human",
};

/// A recipient that is a service, under the `partner-service` profile
/// [`access_project`] adds, at the subject [`READER`] has.
pub const PARTNER_SERVICE: Principal = Principal {
    subject: "reader-1",
    client: "partner-service",
    scope: "documents:read",
    kind: "service",
};

/// The person [`CITIZEN`] is, signed in under the `reader` recipient
/// profile.
pub const CITIZEN_AS_READER: Principal = Principal {
    subject: "citizen-1",
    ..READER
};

/// The starter project with a service recipient profile, `partner-service`,
/// listed by `named-share`, and the `reader` profile listed as a recipient
/// of `institutional-custody`.
pub fn access_project() -> String {
    let project = STARTER_PROJECT
        .replacen(
            "\ndocumentPolicies:\n",
            "  partner-service:\n    principalClaim: sub\n    requiredScopes: [documents:read]\n    requesterClients: [partner-service]\n    actorKind: service\n    role: recipient\n\ndocumentPolicies:\n",
            1,
        )
        .replacen(
            "    recipientProfiles: [staff]\n",
            "    recipientProfiles: [staff, reader]\n",
            1,
        )
        .replacen(
            "    recipientProfiles: [reader, staff]\n",
            "    recipientProfiles: [reader, staff, partner-service]\n",
            1,
        );
    assert_eq!(
        project.matches("partner-service").count(),
        3,
        "the starter project changed shape"
    );
    assert!(project.contains("recipientProfiles: [staff, reader]"));
    project
}

/// The test issuer: one P-256 signing key for the process and the public
/// key set every deployment reads.
pub struct Issuer {
    signing: Vec<u8>,
    pub jwks: String,
}

pub fn issuer() -> &'static Issuer {
    static ISSUER: std::sync::OnceLock<Issuer> = std::sync::OnceLock::new();
    ISSUER.get_or_init(|| {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let signing =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, signing.as_ref()).unwrap();
        let point = pair.public_key().as_ref();
        let jwks = serde_json::json!({"keys": [{
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kid": TEST_KEY_ID,
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..]),
        }]});
        Issuer {
            signing: signing.as_ref().to_vec(),
            jwks: jwks.to_string(),
        }
    })
}

/// Sign an access token for `principal` with `claims` over the ones a
/// real token carries.
pub fn token_with(principal: Principal, claims: serde_json::Value) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut body = serde_json::json!({
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "iat": now,
        "exp": now + 300,
        "sub": principal.subject,
        "azp": principal.client,
        "client_id": principal.client,
        "scope": principal.scope,
        "registry_actor_kind": principal.kind,
    });
    for (key, value) in claims.as_object().unwrap() {
        body[key] = value.clone();
    }
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(TEST_KEY_ID.to_owned());
    header.typ = Some("at+jwt".to_owned());
    jsonwebtoken::encode(
        &header,
        &body,
        &jsonwebtoken::EncodingKey::from_ec_der(&issuer().signing),
    )
    .unwrap()
}

pub fn token(principal: Principal) -> String {
    token_with(principal, serde_json::json!({}))
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

/// The router a prepared runtime serves, called with real tokens.
#[derive(Clone)]
pub struct Api {
    router: axum::Router,
}

/// A request builder already carrying `principal`'s bearer token.
pub fn request(
    principal: Principal,
    method: axum::http::Method,
    path: &str,
) -> axum::http::request::Builder {
    axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {}", token(principal)))
}

impl Api {
    pub fn new(prepared: &registry_documents::runtime::Prepared) -> Self {
        Self {
            router: prepared.router(),
        }
    }

    /// The response to `request`, its body not yet read.
    pub async fn respond(
        &self,
        request: axum::http::Request<axum::body::Body>,
    ) -> axum::response::Response {
        use tower::ServiceExt as _;
        self.router.clone().oneshot(request).await.unwrap()
    }

    pub async fn call(&self, request: axum::http::Request<axum::body::Body>) -> Answer {
        let response = self.respond(request).await;
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

    /// Send `body` as JSON under `principal`, with `key` as the
    /// idempotency key when one is given.
    pub async fn send_json(
        &self,
        principal: Principal,
        method: axum::http::Method,
        path: &str,
        key: Option<&str>,
        body: &serde_json::Value,
    ) -> Answer {
        let mut builder =
            request(principal, method, path).header("content-type", "application/json");
        if let Some(key) = key {
            builder = builder.header("idempotency-key", key);
        }
        self.call(
            builder
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    pub async fn get(&self, principal: Principal, path: &str) -> Answer {
        self.call(
            request(principal, axum::http::Method::GET, path)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
    }

    /// Reserve a document for `custodian` as `principal`.
    pub async fn reserve(
        &self,
        principal: Principal,
        policy: &str,
        custodian: &str,
        content: &[u8],
        media_type: &str,
    ) -> Answer {
        self.reserve_declared(
            principal,
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
        principal: Principal,
        policy: &str,
        custodian: &str,
        digest: &str,
        length: u64,
        media_type: &str,
    ) -> Answer {
        let body = reservation_body(policy, custodian, digest, length, media_type);
        self.reserve_body(principal, &Uuid::new_v4().to_string(), &body)
            .await
    }

    /// Reserve with an exact body under the idempotency key `key`.
    pub async fn reserve_body(
        &self,
        principal: Principal,
        key: &str,
        body: &serde_json::Value,
    ) -> Answer {
        self.send_json(
            principal,
            axum::http::Method::POST,
            "/documents",
            Some(key),
            body,
        )
        .await
    }

    /// Send `body` as the content of the upload at `path`.
    pub async fn put(
        &self,
        principal: Principal,
        path: &str,
        media_type: &str,
        body: axum::body::Body,
    ) -> Answer {
        self.call(
            request(principal, axum::http::Method::PUT, path)
                .header("content-type", media_type)
                .body(body)
                .unwrap(),
        )
        .await
    }

    pub async fn read(&self, principal: Principal, document: &str) -> Answer {
        self.get(principal, &format!("/documents/{document}")).await
    }

    pub async fn download(&self, principal: Principal, document: &str, version: &str) -> Answer {
        self.get(
            principal,
            &format!("/documents/{document}/versions/{version}/content"),
        )
        .await
    }

    /// Issue a grant on `version` to `grantee` as `principal`.
    pub async fn grant(
        &self,
        principal: Principal,
        document: &str,
        version: &str,
        grantee: &str,
        expiry_hours: Option<u32>,
    ) -> Answer {
        self.grant_with_key(
            principal,
            &Uuid::new_v4().to_string(),
            document,
            version,
            grantee,
            expiry_hours,
        )
        .await
    }

    pub async fn grant_with_key(
        &self,
        principal: Principal,
        key: &str,
        document: &str,
        version: &str,
        grantee: &str,
        expiry_hours: Option<u32>,
    ) -> Answer {
        self.grant_kind(
            principal,
            key,
            document,
            version,
            grantee,
            "human",
            expiry_hours,
        )
        .await
    }

    /// Issue a grant naming `grantee` of actor kind `kind`.
    #[allow(clippy::too_many_arguments)]
    pub async fn grant_kind(
        &self,
        principal: Principal,
        key: &str,
        document: &str,
        version: &str,
        grantee: &str,
        kind: &str,
        expiry_hours: Option<u32>,
    ) -> Answer {
        let mut body = serde_json::json!({
            "versionId": version,
            "grantee": {"subject": grantee, "kind": kind},
        });
        if let Some(hours) = expiry_hours {
            body["expiryHours"] = serde_json::json!(hours);
        }
        self.send_json(
            principal,
            axum::http::Method::POST,
            &format!("/documents/{document}/grants"),
            Some(key),
            &body,
        )
        .await
    }

    /// Ask for the erasure of `document` as `principal`.
    pub async fn erase(&self, principal: Principal, document: &str) -> Answer {
        self.call(
            request(
                principal,
                axum::http::Method::POST,
                &format!("/documents/{document}/erasure"),
            )
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
    }

    pub async fn revoke(&self, principal: Principal, grant: &str) -> Answer {
        self.call(
            request(
                principal,
                axum::http::Method::DELETE,
                &format!("/document-grants/{grant}"),
            )
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
    }
}

/// A reservation body.
pub fn reservation_body(
    policy: &str,
    custodian: &str,
    digest: &str,
    length: u64,
    media_type: &str,
) -> serde_json::Value {
    serde_json::json!({
        "policyId": policy,
        "custodian": {"subject": custodian},
        "expectedDigest": digest,
        "length": length,
        "mediaType": media_type,
    })
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
