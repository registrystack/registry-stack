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
    /// The committed DHIS2 Tracker example project.
    pub fn example_project() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter/examples/dhis2-tracker")
    }

    /// The maintained profile the example project pins.
    pub fn example_profile() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/profiles/breg-records/profile.yaml")
    }

    /// The committed GovStack example project: the same DHIS2 pack under the
    /// govstack-consultation profile.
    pub fn govstack_project() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter/examples/dhis2-govstack")
    }

    /// The maintained govstack-consultation profile.
    pub fn govstack_profile() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/profiles/govstack-consultation/profile.yaml")
    }

    /// The maintained profile the project at `project` pins by id.
    fn profile_for(project: &Path) -> std::path::PathBuf {
        let text =
            std::fs::read_to_string(project.join("project.yaml")).expect("the project is readable");
        if text.contains("id: govstack-consultation") {
            Self::govstack_profile()
        } else {
            Self::example_profile()
        }
    }

    /// The maintained pack the example project pins.
    pub fn example_pack() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/packs/dhis2-tracker/pack.yaml")
    }

    pub async fn start(upstream_url: &str) -> Self {
        Self::start_with_project(upstream_url, &Self::example_project()).await
    }

    /// Start over the project directory at `project`.
    pub async fn start_with_project(upstream_url: &str, project: &Path) -> Self {
        let mut served = Self::spawn_with_project(upstream_url, project, CURSOR_KEY).await;
        served.wait_until_listening();
        served
    }

    /// Start over `project` and return the stderr of an adapter that
    /// refuses to start; panics when it starts, or never exits.
    pub async fn refusal_with_project(upstream_url: &str, project: &Path) -> String {
        Self::refusal_with_cursor_key(upstream_url, project, CURSOR_KEY).await
    }

    /// As [`Self::refusal_with_project`], with `cursor_key` as the cursor
    /// key secret.
    pub async fn refusal_with_cursor_key(
        upstream_url: &str,
        project: &Path,
        cursor_key: &str,
    ) -> String {
        let mut served = Self::spawn_with_project(upstream_url, project, cursor_key).await;
        served.await_refusal()
    }

    /// As [`Self::refusal_with_project`], with the upstream username
    /// secret left out of the adapter's environment.
    pub async fn refusal_without_upstream_username(upstream_url: &str, project: &Path) -> String {
        let mut served = Self::spawn_inner(
            upstream_url,
            project,
            CURSOR_KEY,
            &["TEST_UPSTREAM_USERNAME"],
        )
        .await;
        served.await_refusal()
    }

    /// As [`Self::refusal_with_project`], with `cursor_lines` as the
    /// runtime config's cursor members.
    pub async fn refusal_with_cursor_config(
        upstream_url: &str,
        project: &Path,
        cursor_lines: &str,
    ) -> String {
        let mut served =
            Self::spawn_config(upstream_url, project, CURSOR_KEY, &[], cursor_lines).await;
        served.await_refusal()
    }

    async fn spawn_with_project(upstream_url: &str, project: &Path, cursor_key: &str) -> Self {
        Self::spawn_inner(upstream_url, project, cursor_key, &[]).await
    }

    async fn spawn_inner(
        upstream_url: &str,
        project: &Path,
        cursor_key: &str,
        omitted_env: &[&str],
    ) -> Self {
        Self::spawn_config(
            upstream_url,
            project,
            cursor_key,
            omitted_env,
            "cursorKeyRef: secret:env/TEST_CURSOR_KEY\n",
        )
        .await
    }

    /// `cursor_lines` are the runtime config's cursor members, verbatim.
    async fn spawn_config(
        upstream_url: &str,
        project: &Path,
        cursor_key: &str,
        omitted_env: &[&str],
        cursor_lines: &str,
    ) -> Self {
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
allowedClients:
  - synthetic-client
allowedPrivateCidrs:
  - 127.0.0.0/8
audit:
  retentionDays: 90
{cursor_lines}"#
            ),
        )
        .expect("write the runtime config");
        let mut command = Command::new(env!("CARGO_BIN_EXE_adapter"));
        command
            .args(["serve", "--runtime-config"])
            .arg(&runtime)
            .arg("--project")
            .arg(project);
        // The example folder holds only the project; its profile and pack
        // are the maintained artifacts, passed by flag. A project directory
        // that carries its own pair is served from beside the project.
        if !project.join("pack.yaml").exists() {
            command.arg("--pack").arg(Self::example_pack());
        }
        if !project.join("profile.yaml").exists() {
            command.arg("--profile").arg(Self::profile_for(project));
        }
        command
            .env("TEST_UPSTREAM_USERNAME", USERNAME)
            .env("TEST_UPSTREAM_PASSWORD", PASSWORD)
            .env("TEST_DB_URL", &database)
            .env("TEST_JWKS", &jwks)
            .env("TEST_CURSOR_KEY", cursor_key)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        for name in omitted_env {
            command.env_remove(name);
        }
        let child = command.spawn().expect("the adapter binary starts");
        Self {
            child,
            port,
            database,
            key,
            _directory: directory,
        }
    }

    /// The stderr of an adapter that refuses to start; panics when it
    /// starts, or never exits.
    fn await_refusal(&mut self) -> String {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().expect("poll the adapter") {
                assert!(!status.success(), "the adapter exited successfully");
                let mut stderr = String::new();
                if let Some(mut pipe) = self.child.stderr.take() {
                    pipe.read_to_string(&mut stderr).expect("read stderr");
                }
                return stderr;
            }
            assert!(
                TcpStream::connect(("127.0.0.1", self.port)).is_err(),
                "the adapter started serving"
            );
            assert!(Instant::now() < deadline, "the adapter never exited");
            std::thread::sleep(Duration::from_millis(100));
        }
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

    /// Stop the adapter and return what it wrote to stderr.
    pub fn stop_and_read_stderr(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut stderr = String::new();
        if let Some(mut pipe) = self.child.stderr.take() {
            pipe.read_to_string(&mut stderr).expect("read stderr");
        }
        stderr
    }

    /// Run `sql` against the adapter's journal schema.
    pub async fn execute_sql(&self, sql: &str) {
        let (client, connection) = tokio_postgres::connect(&self.database, tokio_postgres::NoTls)
            .await
            .expect("connect the journal schema");
        tokio::spawn(connection);
        client.batch_execute(sql).await.expect("run the statement");
    }

    /// The `kind` of every journal event written so far, sorted by kind.
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

    /// Every journal event's detail, as one text.
    pub async fn journal_text(&self) -> String {
        let (client, connection) = tokio_postgres::connect(&self.database, tokio_postgres::NoTls)
            .await
            .expect("connect the journal schema");
        tokio::spawn(connection);
        client
            .query("SELECT detail::text FROM adapter_journal_events", &[])
            .await
            .expect("read the journal")
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The `detail` of every journal event of `kind`, oldest first.
    pub async fn journal_details(&self, kind: &str) -> Vec<Value> {
        let (client, connection) = tokio_postgres::connect(&self.database, tokio_postgres::NoTls)
            .await
            .expect("connect the journal schema");
        tokio::spawn(connection);
        client
            .query(
                "SELECT detail::text FROM adapter_journal_events \
                 WHERE event_kind = $1 ORDER BY occurred_at",
                &[&kind],
            )
            .await
            .expect("read the journal")
            .iter()
            .map(|row| serde_json::from_str(&row.get::<_, String>(0)).expect("detail is JSON"))
            .collect()
    }

    /// Send one GET, give the adapter time to start the exchange, then drop
    /// the connection without reading the answer.
    pub fn get_and_disconnect(&self, path: &str, bearer: &str) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {bearer}\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).expect("write");
        std::thread::sleep(Duration::from_millis(300));
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
        self.token_with(subject, scope, json!({}))
    }

    /// A token for `subject` holding `scope`, with `extra` claims written
    /// over the standard ones (a client, an assertion issuer, a long `sub`).
    pub fn token_with(&self, subject: &str, scope: &str, extra: Value) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("epoch")
            .as_secs();
        let mut claims = json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": subject,
            "client_id": "synthetic-client",
            "scope": scope,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": format!("jti-{now}-{}", NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)),
        });
        for (name, value) in extra.as_object().expect("extra claims are an object") {
            claims[name] = value.clone();
        }
        sign_compact_jwt_with_key(&self.key, "at+jwt", "canary-resource-key", claims)
    }

    /// One GET over a fresh connection: status, headers, JSON body.
    pub fn get(&self, path: &str, bearer: Option<&str>) -> (u16, String, Value) {
        self.request("GET", path, bearer, &[], b"")
    }

    /// One POST of a JSON body over a fresh connection.
    pub fn post(&self, path: &str, bearer: Option<&str>, body: &Value) -> (u16, String, Value) {
        self.request(
            "POST",
            path,
            bearer,
            &[("Content-Type", "application/json")],
            body.to_string().as_bytes(),
        )
    }

    /// One request over a fresh connection: status, headers, JSON body (the
    /// body text as a string when it is not JSON). A body adds its
    /// Content-Length.
    pub fn request(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (u16, String, Value) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
        if let Some(token) = bearer {
            request.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        if !body.is_empty() {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).expect("write");
        stream.write_all(body).expect("write the body");
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

pub fn copy_example_project(directory: &std::path::Path) {
    copy_project(
        &Served::example_project(),
        &Served::example_profile(),
        directory,
    );
}

/// The govstack example in a copy a test can edit.
pub fn copy_govstack_project(directory: &std::path::Path) {
    copy_project(
        &Served::govstack_project(),
        &Served::govstack_profile(),
        directory,
    );
}

fn copy_project(project: &Path, profile: &Path, directory: &std::path::Path) {
    fn copy(from: &std::path::Path, to: &std::path::Path) {
        std::fs::create_dir_all(to).expect("create the copy directory");
        for entry in std::fs::read_dir(from).expect("read the example directory") {
            let entry = entry.expect("a directory entry");
            let target = to.join(entry.file_name());
            if entry.file_type().expect("a file type").is_dir() {
                copy(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).expect("copy a file");
            }
        }
    }
    copy(project, directory);
    // The example folder holds only the project: the copy carries its own
    // pack, scripts and profile beside it, so a test can edit them.
    let packs = Served::example_pack();
    copy(packs.parent().expect("the pack directory"), directory);
    std::fs::copy(profile, directory.join("profile.yaml")).expect("copy the profile");
}

/// The digest string the pins use for `bytes`.
pub fn digest_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hex: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// Replace one pack script in a copied project and re-pin it: the pack
/// pins the script's digest and the project pins the pack's.
pub fn replace_pack_script(directory: &Path, script: &str, text: &str) {
    let script_path = directory.join(script);
    let old = std::fs::read(&script_path).expect("the script is readable");
    let pack_path = directory.join("pack.yaml");
    let pack = std::fs::read_to_string(&pack_path).expect("the pack is readable");
    let old_pin = digest_of(&old);
    assert!(
        pack.contains(&old_pin),
        "the pack pins the committed script"
    );
    let edited = pack.replace(&old_pin, &digest_of(text.as_bytes()));
    let project_path = directory.join("project.yaml");
    let project = std::fs::read_to_string(&project_path).expect("the project is readable");
    let pinned = digest_of(pack.as_bytes());
    assert!(
        project.contains(&pinned),
        "the project pins the committed pack"
    );
    std::fs::write(&script_path, text).expect("write the script");
    std::fs::write(&pack_path, &edited).expect("write the pack");
    std::fs::write(
        &project_path,
        project.replace(&pinned, &digest_of(edited.as_bytes())),
    )
    .expect("write the project");
}

/// Replace `from` with `to` in a copied project's profile and re-pin it:
/// the project pins the profile's digest.
pub fn replace_profile_text(directory: &Path, from: &str, to: &str) {
    let profile_path = directory.join("profile.yaml");
    let profile = std::fs::read_to_string(&profile_path).expect("the profile is readable");
    assert!(profile.contains(from), "the profile carries the text");
    let edited = profile.replacen(from, to, 1);
    let project_path = directory.join("project.yaml");
    let project = std::fs::read_to_string(&project_path).expect("the project is readable");
    let pinned = digest_of(profile.as_bytes());
    assert!(
        project.contains(&pinned),
        "the project pins the committed profile"
    );
    std::fs::write(&profile_path, &edited).expect("write the profile");
    std::fs::write(
        &project_path,
        project.replace(&pinned, &digest_of(edited.as_bytes())),
    )
    .expect("write the project");
}
