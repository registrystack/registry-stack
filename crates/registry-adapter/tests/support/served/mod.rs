// SPDX-License-Identifier: Apache-2.0

//! The served-binary harness: one running `adapter` process over its own
//! journal schema, the token signer for it, and the committed DHIS2
//! Tracker fixtures. Needs `ADAPTER_TEST_DATABASE_URL`.

#[path = "../upstream/mod.rs"]
pub mod upstream;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use registry_platform_testing::{
    access_token_test_key, jwks_from_private_jwk, sign_compact_jwt_with_key,
};
use serde_json::{json, Value};

pub const ISSUER: &str = "http://127.0.0.1:9";
pub const AUDIENCE: &str = "registry-adapter-test";
pub const USERNAME: &str = "synthetic-reader";
pub const PASSWORD: &str = "synthetic-password";
/// Exactly 32 bytes, the cursor key length.
const CURSOR_KEY: &str = "synthetic-cursor-key-0123456789!";
/// The subject the default token carries.
pub const SUBJECT: &str = "synthetic-caller";

static NEXT_SCHEMA: AtomicU32 = AtomicU32::new(0);

/// The committed fixture directory for the DHIS2 Tracker pack. A fixture is
/// test data, not configuration, so it is read without a config envelope.
#[allow(clippy::disallowed_methods)]
pub fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/adapter/fixtures/dhis2-tracker")
        .join(format!("{name}.yaml"));
    let text = std::fs::read_to_string(&path).expect("the committed fixture is readable");
    serde_norway::from_str(&text).expect("the fixture is YAML")
}

/// The status and body of the first scripted upstream reply of one
/// committed fixture.
pub fn capture(name: &str) -> (u16, String) {
    let document = fixture(name);
    let response = &document["entries"][0]["upstream"][0]["response"];
    let status = u16::try_from(response["status"].as_u64().expect("status")).expect("status");
    (status, response["body"].to_string())
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind a free loopback port")
        .local_addr()
        .expect("local address")
        .port()
}

/// One running `adapter` process over its own journal schema, with the
/// token signer for it.
pub struct Served {
    child: Child,
    pub port: u16,
    pub database: String,
    key: registry_platform_crypto::PrivateJwk,
    _directory: tempfile::TempDir,
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn schema_url() -> String {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
    let serial = NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the test clock is after the Unix epoch")
        .as_nanos();
    let schema = format!("adapter_served_{nanos}_{serial}");
    let (client, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect the adapter test database");
    tokio::spawn(connection);
    client
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create an isolated schema");
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    tokio_postgres::Config::from_str(&url).expect("the scoped url parses");
    url
}

impl Served {
    pub async fn start(upstream_url: &str) -> Self {
        let database = schema_url().await;
        let key = access_token_test_key(jsonwebtoken::Algorithm::ES256);
        let jwks = jwks_from_private_jwk(&key).to_string();
        let port = free_port();
        let directory = tempfile::tempdir().expect("a scratch directory");
        let runtime = directory.path().join("runtime.yaml");
        std::fs::write(
            &runtime,
            format!(
                r#"apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: dhis2-tracker-test
endpoints:
  - endpoint: tracker
    baseUrl: {upstream_url}
    credential:
      type: basic
      usernameRef: secret:env/TEST_UPSTREAM_USERNAME
      passwordRef: secret:env/TEST_UPSTREAM_PASSWORD
listener:
  bind: 127.0.0.1:{port}
database:
  runtimeUrlRef: secret:env/TEST_DB_URL
  migrationUrlRef: secret:env/TEST_DB_URL
  testOnlyPlaintext: true
oidc:
  issuer: {ISSUER}
  audience: {AUDIENCE}
  allowInsecureHttp: true
  jwksSource:
    type: static
    documentRef: secret:env/TEST_JWKS
allowedPrivateCidrs:
  - 127.0.0.0/8
audit:
  retentionDays: 90
cursorKeyRef: secret:env/TEST_CURSOR_KEY
"#
            ),
        )
        .expect("write the runtime config");
        let project = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/examples/dhis2-tracker");
        let child = Command::new(env!("CARGO_BIN_EXE_adapter"))
            .args(["serve", "--runtime-config"])
            .arg(&runtime)
            .arg("--project")
            .arg(&project)
            .env("TEST_UPSTREAM_USERNAME", USERNAME)
            .env("TEST_UPSTREAM_PASSWORD", PASSWORD)
            .env("TEST_DB_URL", &database)
            .env("TEST_JWKS", &jwks)
            .env("TEST_CURSOR_KEY", CURSOR_KEY)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the adapter binary starts");
        let mut served = Self {
            child,
            port,
            database,
            key,
            _directory: directory,
        };
        served.wait_until_listening();
        served
    }

    fn wait_until_listening(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll the adapter") {
                let mut stderr = String::new();
                if let Some(mut pipe) = self.child.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                panic!("the adapter exited early ({status}): {stderr}");
            }
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            assert!(Instant::now() < deadline, "the adapter never listened");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The `kind` of every journal event written so far, oldest first.
    pub async fn journal_kinds(&self) -> Vec<String> {
        let (client, connection) = tokio_postgres::connect(&self.database, tokio_postgres::NoTls)
            .await
            .expect("connect the journal schema");
        tokio::spawn(connection);
        client
            .query(
                "SELECT event_kind FROM adapter_journal_events ORDER BY 1",
                &[],
            )
            .await
            .expect("read the journal")
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect()
    }

    pub fn token(&self, scope: &str) -> String {
        self.token_for(SUBJECT, scope)
    }

    /// A well-formed token signed by a key the adapter does not trust.
    pub fn forged_token() -> String {
        let other = access_token_test_key(jsonwebtoken::Algorithm::ES256);
        sign_compact_jwt_with_key(
            &other,
            "at+jwt",
            "canary-resource-key",
            json!({"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "scope": "records.read",
                   "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 300}),
        )
    }

    /// A token for `subject` holding `scope`.
    pub fn token_for(&self, subject: &str, scope: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("epoch")
            .as_secs();
        sign_compact_jwt_with_key(
            &self.key,
            "at+jwt",
            "canary-resource-key",
            json!({
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": subject,
                "client_id": "synthetic-client",
                "scope": scope,
                "iat": now,
                "nbf": now,
                "exp": now + 300,
                "jti": format!("jti-{now}-{}", NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)),
            }),
        )
    }

    /// One GET over a fresh connection: status, headers, JSON body.
    pub fn get(&self, path: &str, bearer: Option<&str>) -> (u16, String, Value) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
        if let Some(token) = bearer {
            request.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).expect("write");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).expect("read");
        let text = String::from_utf8(raw).expect("utf8");
        let (head, body) = text.split_once("\r\n\r\n").expect("a header block");
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("a status code");
        let json =
            serde_json::from_str(body.trim()).unwrap_or_else(|_| Value::String(body.to_owned()));
        (status, head.to_owned(), json)
    }
}

pub fn expected_basic() -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!("{USERNAME}:{PASSWORD}"))
    )
}
