// SPDX-License-Identifier: Apache-2.0

//! Process and loopback helpers for the real BReg-backed GovStack Write test.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use registry_platform_testing::{
    access_token_test_key, jwks_from_private_jwk, sign_compact_jwt_with_key,
};
use serde_json::{json, Value};

const ISSUER: &str = "http://127.0.0.1:9";
const AUDIENCE: &str = "registry-adapter-breg-write-test";
const CLIENT_ID: &str = "breg-write-client";
const CURSOR_KEY: &str = "breg-write-cursor-key-0123456789";
static NEXT_SCHEMA: AtomicUsize = AtomicUsize::new(0);

pub struct BregDev {
    bregctl: PathBuf,
    docker: PathBuf,
    project: PathBuf,
    _root: tempfile::TempDir,
    pub source_token: String,
    pub origin: String,
}

impl Drop for BregDev {
    fn drop(&mut self) {
        let status = Command::new(&self.bregctl)
            .args(["--format", "json", "dev", "stop"])
            .arg("--docker-bin")
            .arg(&self.docker)
            .arg(&self.project)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !matches!(status, Ok(status) if status.success()) {
            eprintln!("the owned BReg development fixture did not stop cleanly");
        }
    }
}

impl BregDev {
    pub fn start() -> Self {
        let breg = required_executable("BREG_TEST_BREG_BINARY");
        let bregctl = required_executable("BREG_TEST_BREGCTL_BINARY");
        let docker = required_executable("BREG_TEST_DOCKER_BINARY");
        let root = tempfile::tempdir().expect("create BReg scratch directory");
        let project = root.path().join("breg-project");

        let init = Command::new(&bregctl)
            .args(["--format", "json", "init"])
            .arg(&project)
            .output()
            .expect("run bregctl init");
        assert!(
            init.status.success(),
            "bregctl init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        extend_generated_contact_project(&project);

        let database_port = free_port();
        let issuer_port = free_port();
        let breg_port = free_port();
        let started = Command::new(&bregctl)
            .args(["--format", "json", "dev", "start", "--breg-bin"])
            .arg(&breg)
            .arg("--docker-bin")
            .arg(&docker)
            .arg("--breg-port")
            .arg(breg_port.to_string())
            .arg("--issuer-port")
            .arg(issuer_port.to_string())
            .arg("--database-port")
            .arg(database_port.to_string())
            .arg(&project)
            .output()
            .expect("run bregctl dev start");
        if !started.status.success() {
            panic!(
                "bregctl dev start failed: {}\n{}\n{}",
                String::from_utf8_lossy(&started.stdout),
                String::from_utf8_lossy(&started.stderr),
                dev_log_excerpt(&project, "inspect-list")
            );
        }
        let report: Value =
            serde_json::from_slice(&started.stdout).expect("dev start report is JSON");
        assert_eq!(report["ok"], true, "{report}");
        assert_eq!(report["status"], "complete", "{report}");
        assert_eq!(report["outcome"], "ready", "{report}");
        let origin = report["bregUrl"]
            .as_str()
            .expect("dev report carries bregUrl")
            .trim_end_matches('/')
            .to_owned();

        let token = Command::new(&bregctl)
            .args(["--format", "json", "dev", "token", "editor"])
            .arg(&project)
            .output()
            .expect("run bregctl dev token");
        assert!(
            token.status.success(),
            "bregctl dev token failed: {}\n{}",
            String::from_utf8_lossy(&token.stdout),
            String::from_utf8_lossy(&token.stderr)
        );
        let report: Value =
            serde_json::from_slice(&token.stdout).expect("dev token report is JSON");
        let header_file = report["headerFile"]
            .as_str()
            .expect("token report carries headerFile");
        let header = std::fs::read_to_string(header_file).expect("read private token header");
        let source_token = header
            .trim()
            .strip_prefix("Authorization: Bearer ")
            .expect("token header uses Bearer")
            .to_owned();
        assert_eq!(source_token.split('.').count(), 3, "compact source token");

        Self {
            bregctl,
            docker,
            project,
            _root: root,
            source_token,
            origin,
        }
    }
}

fn dev_log_excerpt(project: &Path, stem: &str) -> String {
    let directory = project.join(".breg/dev/logs");
    let Ok(entries) = std::fs::read_dir(&directory) else {
        return "the private development log directory is unavailable".to_owned();
    };
    let mut excerpt = String::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.contains(stem) {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        let bytes = &bytes[..bytes.len().min(16 * 1024)];
        excerpt.push_str(&format!("{name}: {}\n", String::from_utf8_lossy(bytes)));
    }
    if excerpt.is_empty() {
        format!("no {stem} development log was retained")
    } else {
        excerpt
    }
}

fn required_executable(name: &str) -> PathBuf {
    let path = PathBuf::from(std::env::var_os(name).unwrap_or_else(|| {
        panic!("{name} must name the absolute executable for the real BReg journey")
    }));
    assert!(path.is_absolute(), "{name} must be absolute");
    assert!(path.is_file(), "{name} must be an executable file");
    path
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve loopback port")
        .local_addr()
        .expect("reserved address")
        .port()
}

fn replace_once(text: &mut String, from: &str, to: &str) {
    let replaced = text.replacen(from, to, 1);
    assert_ne!(*text, replaced, "generated project contains {from:?}");
    *text = replaced;
}

fn extend_generated_contact_project(project: &Path) {
    let registry = project.join("registry.yaml");
    let mut text = std::fs::read_to_string(&registry).expect("read generated registry");
    replace_once(
        &mut text,
        "    mutationMode: mutable\n",
        "    mutationMode: mutable\n    batch: {maximumItems: 1, maximumBytes: 8192}\n",
    );
    replace_once(
        &mut text,
        "      - {id: jurisdiction, type: string, required: true, minimumLength: 1, maximumLength: 40, classification: internal}\n",
        "      - {id: jurisdiction, type: string, required: true, minimumLength: 1, maximumLength: 40, classification: internal}\n      - {id: note, type: string, required: false, minimumLength: 1, maximumLength: 240, classification: internal}\n",
    );
    replace_once(
        &mut text,
        "          operations: [create, get, list, patch]\n",
        "          operations: [create, get, list, patch, batch]\n",
    );
    replace_once(
        &mut text,
        "          readableFields: [name, email, jurisdiction]\n",
        "          readableFields: [name, email, jurisdiction, note]\n",
    );
    replace_once(
        &mut text,
        "          writableFields: [name, email, jurisdiction]\n",
        "          writableFields: [name, email, jurisdiction, note]\n",
    );
    std::fs::write(registry, text).expect("write extended generated registry");
}

#[derive(Clone, Debug)]
pub struct SourceRequest {
    pub method: String,
    pub target: String,
    pub idempotency_key: Option<String>,
    pub body: Vec<u8>,
    pub response_body: Option<Vec<u8>>,
}

pub struct DropProxy {
    port: u16,
    requests: Arc<Mutex<Vec<SourceRequest>>>,
    drop_next: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for DropProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl DropProxy {
    pub fn start(origin: &str) -> Self {
        let upstream = origin
            .strip_prefix("http://")
            .expect("breg dev uses loopback HTTP")
            .parse::<SocketAddr>()
            .expect("breg origin is a socket address");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind source proxy");
        let port = listener.local_addr().expect("proxy address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let drop_next = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_drop = Arc::clone(&drop_next);
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            for accepted in listener.incoming() {
                let Ok(mut client) = accepted else { break };
                if thread_stop.load(Ordering::SeqCst) {
                    break;
                }
                let requests = Arc::clone(&thread_requests);
                let drop_next = Arc::clone(&thread_drop);
                std::thread::spawn(move || proxy_one(&mut client, upstream, &requests, &drop_next));
            }
        });
        Self {
            port,
            requests,
            drop_next,
            stop,
            thread: Some(thread),
        }
    }

    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn arm_response_drop(&self) {
        assert!(
            !self.drop_next.swap(true, Ordering::SeqCst),
            "only one response drop may be armed"
        );
    }

    pub fn requests(&self) -> Vec<SourceRequest> {
        self.requests.lock().expect("source request log").clone()
    }
}

fn proxy_one(
    client: &mut TcpStream,
    upstream: SocketAddr,
    requests: &Arc<Mutex<Vec<SourceRequest>>>,
    drop_next: &Arc<AtomicBool>,
) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(15)));
    let Ok((head, body)) = read_http_request(client) else {
        return;
    };
    let mut lines = head.split("\r\n");
    let Some(request_line) = lines.next() else {
        return;
    };
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_owned();
    let target = request_parts.next().unwrap_or_default().to_owned();
    let mut idempotency_key = None;
    let mut forwarded = format!("{request_line}\r\n");
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return;
        };
        if name.eq_ignore_ascii_case("idempotency-key") {
            idempotency_key = Some(value.trim().to_owned());
        }
        if !name.eq_ignore_ascii_case("connection") {
            forwarded.push_str(line);
            forwarded.push_str("\r\n");
        }
    }
    forwarded.push_str("Connection: close\r\n\r\n");
    let request_index = {
        let mut requests = requests.lock().expect("source request log");
        let index = requests.len();
        requests.push(SourceRequest {
            method,
            target,
            idempotency_key,
            body: body.clone(),
            response_body: None,
        });
        index
    };

    let Ok(mut source) = TcpStream::connect_timeout(&upstream, Duration::from_secs(10)) else {
        return;
    };
    let _ = source.set_read_timeout(Some(Duration::from_secs(15)));
    if source.write_all(forwarded.as_bytes()).is_err() || source.write_all(&body).is_err() {
        return;
    }
    let mut response = Vec::new();
    if source.read_to_end(&mut response).is_err() {
        return;
    }
    if let Some(boundary) = response.windows(4).position(|part| part == b"\r\n\r\n") {
        requests.lock().expect("source request log")[request_index].response_body =
            Some(response[boundary + 4..].to_vec());
    }
    if !drop_next.swap(false, Ordering::SeqCst) {
        let _ = client.write_all(&response);
    }
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<(String, Vec<u8>)> {
    let mut bytes = Vec::new();
    let mut one = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut one)?;
        bytes.push(one[0]);
        if bytes.len() > 65_536 {
            return Err(std::io::Error::other("request header too large"));
        }
    }
    let head = String::from_utf8(bytes)
        .map_err(|_| std::io::Error::other("request header is not UTF-8"))?;
    let content_length = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .transpose()
        .map_err(|_| std::io::Error::other("invalid content length"))?
        .unwrap_or(0);
    let mut body = vec![0; content_length];
    stream.read_exact(&mut body)?;
    Ok((head, body))
}

pub struct AdapterProcess {
    child: Child,
    pub port: u16,
    key: registry_platform_crypto::PrivateJwk,
    stderr: Arc<Mutex<String>>,
    reader: Option<JoinHandle<()>>,
    _root: tempfile::TempDir,
}

impl Drop for AdapterProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl AdapterProcess {
    pub async fn start(
        source_origin: &str,
        source_token: &str,
        project: &Path,
        pack: &Path,
    ) -> Self {
        let database = isolated_adapter_database().await;
        let key = access_token_test_key(jsonwebtoken::Algorithm::ES256);
        let jwks = jwks_from_private_jwk(&key).to_string();
        let root = tempfile::tempdir().expect("create Adapter scratch directory");
        let runtime = root.path().join("runtime.yaml");
        std::fs::write(
            &runtime,
            format!(
                r#"apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: breg-govstack-native-test
endpoints:
  - endpoint: registry
    baseUrl: {source_origin}
    credential:
      type: static-authorization
      tokenRef: secret:env/TEST_BREG_SOURCE_TOKEN
listener:
  bind: 127.0.0.1:0
database:
  runtimeUrlRef: secret:env/TEST_ADAPTER_DB_URL
  migrationUrlRef: secret:env/TEST_ADAPTER_DB_URL
  testOnlyPlaintext: true
oidc:
  issuer: {ISSUER}
  audience: {AUDIENCE}
  allowInsecureHttp: true
  jwksSource:
    type: static
    documentRef: secret:env/TEST_ADAPTER_JWKS
allowedClients: [{CLIENT_ID}]
allowedPrivateCidrs: [192.168.0.0/16]
audit:
  retentionDays: 90
idempotency:
  responseRetentionSeconds: 86400
cursorKeyRef: secret:env/TEST_ADAPTER_CURSOR_KEY
"#
            ),
        )
        .expect("write Adapter runtime");
        let mut child = Command::new(env!("CARGO_BIN_EXE_adapter"))
            .args(["serve", "--runtime-config"])
            .arg(&runtime)
            .arg("--project")
            .arg(project)
            .arg("--pack")
            .arg(pack)
            .env("TEST_BREG_SOURCE_TOKEN", source_token)
            .env("TEST_ADAPTER_DB_URL", database)
            .env("TEST_ADAPTER_JWKS", jwks)
            .env("TEST_ADAPTER_CURSOR_KEY", CURSOR_KEY)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start Adapter process");
        let pipe = child.stderr.take().expect("Adapter stderr pipe");
        let stderr = Arc::new(Mutex::new(String::new()));
        let collected = Arc::clone(&stderr);
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut pipe = BufReader::new(pipe);
            let mut line = String::new();
            while pipe.read_line(&mut line).unwrap_or(0) != 0 {
                if let Some(port) = listening_port(&line) {
                    let _ = sender.send(port);
                }
                collected
                    .lock()
                    .expect("Adapter stderr log")
                    .push_str(&line);
                line.clear();
            }
        });
        let deadline = Instant::now() + Duration::from_secs(45);
        let port = loop {
            if let Ok(port) = receiver.recv_timeout(Duration::from_millis(100)) {
                break port;
            }
            if let Some(status) = child.try_wait().expect("poll Adapter process") {
                panic!(
                    "Adapter exited early ({status}): {}",
                    stderr.lock().expect("Adapter stderr log")
                );
            }
            assert!(Instant::now() < deadline, "Adapter did not listen");
        };
        Self {
            child,
            port,
            key,
            stderr,
            reader: Some(reader),
            _root: root,
        }
    }

    pub fn token(&self, scope: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock follows epoch")
            .as_secs();
        sign_compact_jwt_with_key(
            &self.key,
            "at+jwt",
            "canary-resource-key",
            json!({
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": "synthetic-facade-caller",
                "client_id": CLIENT_ID,
                "scope": scope,
                "iat": now,
                "nbf": now,
                "exp": now + 600,
                "jti": format!("breg-write-{now}-{scope}"),
            }),
        )
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        token: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> HttpResponse {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect to Adapter");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("set Adapter response timeout");
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nAccept: application/json\r\n"
        );
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        if !body.is_empty() {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .expect("write Adapter request");
        stream.write_all(body).expect("write Adapter request body");
        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .expect("read Adapter response");
        HttpResponse::parse(bytes)
    }

    pub fn stderr(&self) -> String {
        self.stderr.lock().expect("Adapter stderr log").clone()
    }
}

fn listening_port(line: &str) -> Option<u16> {
    let event: Value = serde_json::from_str(line.trim()).ok()?;
    if event["fields"]["message"] != "listening" {
        return None;
    }
    event["fields"]["address"]
        .as_str()?
        .parse::<SocketAddr>()
        .ok()
        .map(|address| address.port())
}

async fn isolated_adapter_database() -> String {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL is required for the real Adapter journey");
    let serial = NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock follows epoch")
        .as_nanos();
    let schema = format!("adapter_breg_write_{nanos}_{serial}");
    let (client, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect Adapter test PostgreSQL");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create isolated Adapter schema");
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
    tokio_postgres::Config::from_str(&scoped).expect("scoped database URL parses");
    scoped
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    fn parse(bytes: Vec<u8>) -> Self {
        let boundary = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("response has header block");
        let head = std::str::from_utf8(&bytes[..boundary]).expect("response headers are text");
        let mut lines = head.lines();
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .expect("response status");
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        Self {
            status,
            headers,
            body: bytes[boundary + 4..].to_vec(),
        }
    }

    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(&name.to_ascii_lowercase())
            .unwrap_or_else(|| panic!("response carries {name}: {self:?}"))
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|_| panic!("response body is JSON: {self:?}"))
    }
}

pub fn json_body(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).expect("serialize request JSON")
}

pub fn batch_requests(requests: &[SourceRequest]) -> Vec<&SourceRequest> {
    requests
        .iter()
        .filter(|request| request.method == "POST" && request.target.contains(":batch"))
        .collect()
}
