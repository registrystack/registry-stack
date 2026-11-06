// SPDX-License-Identifier: Apache-2.0

//! Serve tests for the seal route: the real `registry-render` binary sealing
//! the `sealed-notice` test bundle with a seal from a throwaway test PKI,
//! timestamped by a loopback RFC 3161 authority, under a test OIDC issuer.
//! Every key is generated at test time; nothing leaves the loopback
//! interface.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use registry_platform_crypto::document_signature::test_support::{
    refuse_timestamp_request, respond_to_timestamp_request, respond_to_timestamp_request_with,
    verify_detached_signature, EssAttribute, TestPki, TestSeal, TEST_SEAL_ORGANIZATION,
};
use registry_platform_crypto::{
    generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk, SigningAlgorithm,
};
use sha2::{Digest, Sha256};

const LIMITS: &str = "limits:\n  renderTimeoutSeconds: 20\n  maximumOutputBytes: 8388608\n  maximumRequestBytes: 8388608\n  maximumConcurrentRenders: 2\n";
const NOTICE_BODY: &str =
    r#"{"issuedAt":"2026-09-16T10:32:00Z","data":{"reference":"N-1","body":"Hello."}}"#;
const SEAL_CLIENT: &str = "records-service";
const OTHER_CLIENT: &str = "portal";
/// The envelope the template receives for `NOTICE_BODY`, as RFC 8785 bytes,
/// before the seal route adds its `signing` member.
const PLAIN_ENVELOPE: &str = r#"{"assets":{},"data":{"body":"Hello.","reference":"N-1"},"document":{"id":"notice","version":2},"issuedAt":"2026-09-16T10:32:00Z","labels":{}}"#;

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn base64_decode(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .expect("base64")
}

fn write_secret(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn physical_tempdir() -> PathBuf {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().canonicalize().expect("physical tempdir path");
    let _ = dir.keep();
    path
}

fn free_port() -> u16 {
    static ISSUED_PORTS: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());
    let mut issued = ISSUED_PORTS.lock().expect("issued test ports");
    for _ in 0..1024 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind for port discovery");
        let port = listener.local_addr().expect("local addr").port();
        if issued.insert(port) {
            return port;
        }
    }
    panic!("could not allocate a distinct fixture port");
}

fn now_seconds() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("whole second")
}

// ----- Loopback timestamp authority -----

#[derive(Clone, Copy)]
enum TsaMode {
    Grant,
    Reject,
    ServerError,
    Oversize,
    Garbage,
    /// Read the query and never answer within the attempt timeout.
    Silent,
    /// Grant a token whose signer carries no ESS signing-certificate
    /// attribute.
    Unbound,
}

struct Tsa {
    port: u16,
    requests: Arc<AtomicUsize>,
    content_types: Arc<Mutex<Vec<String>>>,
    /// The root certificate the authority's timestamp chain leads to.
    root_pem: String,
}

fn read_http_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let split = loop {
        let n = stream.read(&mut buf).expect("read request");
        assert!(n > 0, "the request ended before its headers");
        raw.extend_from_slice(&buf[..n]);
        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
    };
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let length: usize = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
        .expect("content-length");
    let mut body = raw[split + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut buf).expect("read body");
        assert!(n > 0, "the request ended before its body");
        body.extend_from_slice(&buf[..n]);
    }
    (head, body)
}

fn start_tsa(mode: TsaMode) -> Tsa {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tsa");
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(AtomicUsize::new(0));
    let content_types = Arc::new(Mutex::new(Vec::new()));
    let (counter, seen) = (Arc::clone(&requests), Arc::clone(&content_types));
    let pki = TestPki::generate().expect("tsa pki");
    let root_pem = pki.root_certificate_pem();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            counter.fetch_add(1, Ordering::SeqCst);
            let (head, query) = read_http_request(&mut stream);
            let content_type = head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| value.trim().to_owned())
                .unwrap_or_default();
            seen.lock().unwrap().push(content_type);
            if matches!(mode, TsaMode::Silent) {
                std::thread::sleep(Duration::from_secs(10));
                continue;
            }
            let reply = "application/timestamp-reply";
            let (status, content_type, body) = match mode {
                TsaMode::Grant => (
                    "200 OK",
                    reply,
                    respond_to_timestamp_request(&query, &pki, now_seconds()).expect("grant"),
                ),
                TsaMode::Reject => (
                    "200 OK",
                    reply,
                    refuse_timestamp_request(&query, &pki).expect("reject"),
                ),
                TsaMode::ServerError => (
                    "500 Internal Server Error",
                    "text/plain",
                    b"unavailable".to_vec(),
                ),
                TsaMode::Oversize => ("200 OK", reply, vec![0x30; 70 * 1024]),
                TsaMode::Garbage => ("200 OK", reply, b"not a timestamp reply".to_vec()),
                TsaMode::Unbound => (
                    "200 OK",
                    reply,
                    respond_to_timestamp_request_with(
                        &query,
                        &pki,
                        now_seconds(),
                        EssAttribute::Absent,
                    )
                    .expect("grant"),
                ),
                TsaMode::Silent => unreachable!("a silent authority never answers"),
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    Tsa {
        port,
        requests,
        content_types,
        root_pem,
    }
}

// ----- Deployment -----

/// How the fixture declares its one seal.
struct SealSpec {
    /// `timestampAuthority` url, or `None` for the named B-B choice.
    tsa_url: Option<String>,
    /// The seal certificate and key; `key_of` replaces the private key with
    /// another seal's.
    seal: TestSeal,
    key_of: Option<TestSeal>,
}

struct Fixture {
    home: PathBuf,
    runtime_path: PathBuf,
    oidc_key: PrivateJwk,
}

fn seal_pki() -> TestPki {
    TestPki::generate().expect("seal pki")
}

/// The seal key as the secret file holds it. `PrivateJwk` serializes only
/// its public half, so the private members are written out here.
fn private_jwk_json(jwk: &PrivateJwk) -> String {
    let mut members = serde_json::Map::new();
    members.insert("kty".to_owned(), jwk.kty.clone().into());
    for (name, value) in [
        ("kid", &jwk.kid),
        ("alg", &jwk.alg),
        ("crv", &jwk.crv),
        ("x", &jwk.x),
        ("y", &jwk.y),
        ("d", &jwk.d),
    ] {
        if let Some(value) = value {
            members.insert(name.to_owned(), value.clone().into());
        }
    }
    serde_json::Value::Object(members).to_string()
}

fn package(home: &Path) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sealed-notice");
    let output = home.join("package");
    let packaged = Command::new(env!("CARGO_BIN_EXE_registry-render"))
        .args(["package", "--bundle"])
        .arg(&source)
        .arg("--output")
        .arg(&output)
        .output()
        .expect("run registry-render package");
    assert!(
        packaged.status.success(),
        "{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    output
}

fn deployment(seal: Option<SealSpec>) -> Fixture {
    let home = physical_tempdir();
    let package = package(&home);
    std::fs::create_dir(home.join("audit")).unwrap();
    let oidc_key = generate_private_jwk(GeneratedKeyAlgorithm::Es256).unwrap();
    write_secret(
        &home.join("jwks.json"),
        &serde_json::json!({"keys":[oidc_key.public()]}).to_string(),
    );
    let signing = match seal {
        None => String::new(),
        Some(spec) => {
            std::fs::write(home.join("chain.pem"), spec.seal.chain_pem()).unwrap();
            let key = spec.key_of.as_ref().unwrap_or(&spec.seal);
            write_secret(&home.join("seal.jwk"), &private_jwk_json(key.private_jwk()));
            let timestamp = match spec.tsa_url {
                Some(url) => format!(
                    "      timestampAuthority:\n        url: {url}\n        attemptTimeoutMilliseconds: 2000\n"
                ),
                None => "      withoutTimestamp: seal-stops-validating-when-certificate-expires\n"
                    .to_owned(),
            };
            format!(
                "signing:\n  seals:\n    ministry:\n      privateKeyRef: secret:file/seal.jwk\n      certificateChainFile: {}\n{timestamp}      allowedClients: [{SEAL_CLIENT}]\n      trust: test-only\n",
                home.join("chain.pem").display()
            )
        }
    };
    let runtime = format!(
        "apiVersion: id.registrystack.org/formats/render/runtime/v1alpha1\nkind: RenderRuntimeConfig\nlistener:\n  bind: 127.0.0.1:{}\n  shutdownGraceMilliseconds: 5000\npackage:\n  root: {}\nsecretProviders:\n  file:\n    root: {}\nauth:\n  oidc:\n    issuer: https://issuer.example.test\n    audience: urn:render:test\n    allowedClients: [{OTHER_CLIENT}, {SEAL_CLIENT}]\n    jwksSource:\n      type: static\n      documentRef: secret:file/jwks.json\n{LIMITS}audit:\n  path: {}\n{signing}",
        free_port(),
        package.display(),
        home.display(),
        home.join("audit/render.jsonl").display()
    );
    let runtime_path = home.join("runtime.yaml");
    std::fs::write(&runtime_path, runtime).unwrap();
    Fixture {
        home,
        runtime_path,
        oidc_key,
    }
}

fn sealed(tsa: Option<&Tsa>) -> Fixture {
    sealed_by(&seal_pki(), tsa)
}

/// [`sealed`] with a seal certificate `pki` issues.
fn sealed_by(pki: &TestPki, tsa: Option<&Tsa>) -> Fixture {
    deployment(Some(SealSpec {
        tsa_url: tsa.map(|tsa| format!("http://127.0.0.1:{}/tsr", tsa.port)),
        seal: pki.issue_seal(SigningAlgorithm::Es256).unwrap(),
        key_of: None,
    }))
}

impl Fixture {
    fn token(&self, scope: &str, client: &str) -> String {
        let now = chrono::Utc::now().timestamp();
        let header = serde_json::json!({"alg":"ES256","kid":self.oidc_key.kid,"typ":"at+jwt"});
        let claims = serde_json::json!({"iss":"https://issuer.example.test","sub":"canary-principal","client_id":client,"aud":"urn:render:test","iat":now,"exp":now+300,"scope":scope});
        let encoded = |value: &serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(value).unwrap())
        };
        let input = format!("{}.{}", encoded(&header), encoded(&claims));
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sign(input.as_bytes(), &self.oidc_key).unwrap());
        format!("{input}.{signature}")
    }

    fn port(&self) -> u16 {
        std::fs::read_to_string(&self.runtime_path)
            .unwrap()
            .lines()
            .find(|l| l.contains("bind:"))
            .and_then(|l| l.rsplit(':').next())
            .and_then(|p| p.trim().parse().ok())
            .expect("port from runtime")
    }

    fn audit(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.home.join("audit/render.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("one JSON entry per line"))
            .collect()
    }
}

struct Server {
    child: Child,
    port: u16,
    /// The server's standard error: its JSON log lines.
    stderr: std::fs::File,
}

impl Server {
    /// The JSON log lines the server has written so far.
    fn log(&self) -> Vec<serde_json::Value> {
        use std::io::{Seek as _, SeekFrom};
        let mut stderr = self.stderr.try_clone().expect("server stderr handle");
        let mut output = String::new();
        stderr.seek(SeekFrom::Start(0)).unwrap();
        stderr.read_to_string(&mut output).unwrap();
        output
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start `serve` and wait until it listens. Another socket can take the
/// port before the child binds it, so a refused bind retries on a fresh one.
fn start_server(fixture: &Fixture) -> Server {
    for _ in 0..4 {
        if let Some(server) = try_start_server(fixture) {
            return server;
        }
        let text = std::fs::read_to_string(&fixture.runtime_path).unwrap();
        let bind = text.lines().find(|l| l.contains("bind:")).unwrap();
        let (address, _) = bind.rsplit_once(':').unwrap();
        let moved = text.replacen(bind, &format!("{address}:{}", free_port()), 1);
        std::fs::write(&fixture.runtime_path, moved).unwrap();
    }
    panic!("the server port was taken on every attempt");
}

fn try_start_server(fixture: &Fixture) -> Option<Server> {
    // Standard error goes to a file: an undrained pipe could fill and stall
    // the server.
    let mut stderr = tempfile::tempfile().expect("server stderr file");
    let mut child = Command::new(env!("CARGO_BIN_EXE_registry-render"))
        .arg("serve")
        .arg("--runtime-config")
        .arg(&fixture.runtime_path)
        .stdout(Stdio::null())
        .stderr(stderr.try_clone().expect("server stderr handle"))
        .spawn()
        .expect("spawn registry-render serve");
    let port = fixture.port();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().expect("server status") {
            use std::io::{Seek as _, SeekFrom};
            let mut output = String::new();
            stderr.seek(SeekFrom::Start(0)).unwrap();
            stderr.read_to_string(&mut output).unwrap();
            if output.contains("Address already in use") {
                return None;
            }
            panic!("server exited early with {status}:\n{output}");
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(Server {
                child,
                port,
                stderr,
            });
        }
        assert!(
            Instant::now() < deadline,
            "server did not listen within 30s"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Run `serve` expecting it to refuse startup; returns its exit code and
/// standard error.
/// Run serve on a fixture it must refuse, and return its exit code and
/// standard error. A serve that is still running after the deadline started
/// instead of refusing: it is stopped and the test fails rather than hangs.
fn refused_startup(fixture: &Fixture) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_registry-render"))
        .arg("serve")
        .arg("--runtime-config")
        .arg(&fixture.runtime_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn registry-render serve");
    let mut pipe = child.stderr.take().expect("serve stderr");
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        pipe.read_to_string(&mut text).expect("read serve stderr");
        text
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("serve status") {
            break status;
        }
        if Instant::now() > deadline {
            child.kill().expect("stop serve");
            child.wait().expect("serve stops");
            panic!("serve started instead of refusing its runtime");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    (status.code(), reader.join().expect("stderr reader"))
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&self.body)))
    }
}

fn request(
    port: u16,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Reply {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let mut wire =
        format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (name, value) in headers {
        wire.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        wire.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    wire.push_str("\r\n");
    stream.write_all(wire.as_bytes()).unwrap();
    if let Some(body) = body {
        stream.write_all(body.as_bytes()).unwrap();
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .expect("status");
    let headers = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Reply {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

fn post(server: &Server, route: &str, token: &str, accept: &str) -> Reply {
    let bearer = format!("Bearer {token}");
    request(
        server.port,
        "POST",
        route,
        &[
            ("Authorization", bearer.as_str()),
            ("Content-Type", "application/json"),
            ("Accept", accept),
        ],
        Some(NOTICE_BODY),
    )
}

fn seal_json(fixture: &Fixture, server: &Server) -> serde_json::Value {
    let reply = post(
        server,
        "/v1/seal/notice",
        &fixture.token("render:seal", SEAL_CLIENT),
        "application/json",
    );
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    reply.json()
}

// ----- The first revision, rendered independently -----

/// The notice as the seal route's worker renders it, rendered here in
/// process from the same package: the exact first revision a sealed file
/// must start with.
fn first_revision(fixture: &Fixture) -> registry_render::Rendered {
    first_revision_of(fixture, "notice")
}

/// [`first_revision`] for the document type `id`.
fn first_revision_of(fixture: &Fixture, id: &str) -> registry_render::Rendered {
    let root = fixture.home.join("package");
    let verified = registry_platform_config::package::verify_package(
        &root,
        &registry_render::runtime::package_limits(),
        "registry-render package",
    )
    .expect("shared package envelope");
    let bundle = registry_render::Bundle::load_package(&root, &verified).expect("package");
    let document = bundle.document(id).expect("the document type").clone();
    let body: serde_json::Value = serde_json::from_str(NOTICE_BODY).unwrap();
    let request = registry_render::RenderRequest {
        locale: None,
        data: body["data"].clone(),
        assets: std::collections::BTreeMap::new(),
        issued_at: chrono::DateTime::parse_from_rfc3339(body["issuedAt"].as_str().unwrap())
            .unwrap()
            .with_timezone(&chrono::Utc),
    };
    let signing = registry_render::envelope::SigningPayload {
        signer_name: Some(TEST_SEAL_ORGANIZATION.to_owned()),
        test_only: true,
    };
    registry_render::render::render_for_sealing(
        &bundle,
        &document,
        &request,
        &signing,
        false,
        registry_render::DEFAULT_MAX_OUTPUT_BYTES,
    )
    .expect("the first revision renders")
}

// ----- Reading a sealed file the way a validator starts -----

struct SignedFile {
    signed_parts: [Vec<u8>; 2],
    cms_der: Vec<u8>,
    /// The bytes `/Contents` reserves for the signature: half its hex
    /// digits.
    reserved: usize,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The length of a DER value from its tag and length octets.
fn der_len(der: &[u8]) -> usize {
    assert_eq!(der[0], 0x30, "a CMS ContentInfo is a SEQUENCE");
    match der[1] {
        short if short < 0x80 => 2 + usize::from(short),
        long => {
            let count = usize::from(long & 0x7f);
            let length = der[2..2 + count]
                .iter()
                .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
            2 + count + length
        }
    }
}

/// The signed byte ranges and the CMS of a file whose incremental update
/// starts after `first_revision_len` bytes.
fn read_signed_file(pdf: &[u8], first_revision_len: usize) -> SignedFile {
    let update = &pdf[first_revision_len..];
    let at = first_revision_len + find(update, b"/ByteRange [").expect("a ByteRange");
    let close = at + find(&pdf[at..], b"]").expect("ByteRange end");
    let values: Vec<usize> = std::str::from_utf8(&pdf[at + 12..close])
        .unwrap()
        .split_whitespace()
        .map(|n| n.parse().unwrap())
        .collect();
    let [start, gap_start, gap_end, tail] = values[..] else {
        panic!("four ByteRange values: {values:?}")
    };
    assert_eq!(start, 0);
    assert_eq!(gap_end + tail, pdf.len(), "the byte range covers the file");
    let hex_digits = &pdf[gap_start + 1..gap_end - 1];
    let contents = hex::decode(hex_digits).expect("hex contents");
    let cms_der = contents[..der_len(&contents)].to_vec();
    assert!(
        contents[cms_der.len()..].iter().all(|b| *b == 0),
        "the reserved space after the CMS is zero padding"
    );
    SignedFile {
        signed_parts: [pdf[..gap_start].to_vec(), pdf[gap_end..].to_vec()],
        cms_der,
        reserved: contents.len(),
    }
}

// ----- Tests -----

#[test]
fn a_b_t_seal_verifies_over_its_byte_ranges_and_carries_its_timestamp() {
    let tsa = start_tsa(TsaMode::Grant);
    let fixture = sealed(Some(&tsa));
    let server = start_server(&fixture);
    let body = seal_json(&fixture, &server);
    let pdf = base64_decode(body["pdfBase64"].as_str().unwrap());
    assert!(body.get("pdfSha256").is_none(), "{body}");
    assert_eq!(body["signedFileSha256"], sha256_hex(&pdf));
    assert_eq!(body["documentVersion"], "notice v2");
    assert_eq!(body["warnings"], serde_json::json!([]));
    assert_eq!(body["seal"]["id"], "ministry");
    assert_eq!(body["seal"]["level"], "b-t");

    let expected = first_revision(&fixture);
    assert!(
        pdf.starts_with(&expected.pdf),
        "the sealed file starts with the exact first revision"
    );
    assert_eq!(
        body["documentSha256"], expected.pdf_sha256,
        "documentSha256 is the first revision"
    );
    assert_eq!(body["dataSha256"], expected.data_sha256);
    // A client holding only `render:seal` pins the package from the answer.
    assert_eq!(body["bundleHash"], expected.bundle_hash);
    let signed = read_signed_file(&pdf, expected.pdf.len());
    let parts = [
        signed.signed_parts[0].as_slice(),
        signed.signed_parts[1].as_slice(),
    ];
    let verified = verify_detached_signature(&signed.cms_der, &parts).expect("the CMS verifies");
    assert_eq!(
        body["seal"]["certificateSha256"],
        verified.signer_fingerprint.to_string()
    );
    let gen_time = verified
        .timestamp_gen_time
        .expect("B-T carries a timestamp");
    let reported = time::OffsetDateTime::parse(
        body["seal"]["timestampTime"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(reported, gen_time);
    assert_eq!(tsa.requests.load(Ordering::SeqCst), 1, "one attempt");
    assert_eq!(
        tsa.content_types.lock().unwrap().as_slice(),
        ["application/timestamp-query"]
    );

    // The first revision is byte-stable on the seal route.
    let again = seal_json(&fixture, &server);
    assert_eq!(again["documentSha256"], body["documentSha256"]);
    let again_pdf = base64_decode(again["pdfBase64"].as_str().unwrap());
    assert!(again_pdf.starts_with(&expected.pdf));
}

#[test]
fn the_pdf_representation_carries_the_seal_in_headers() {
    let tsa = start_tsa(TsaMode::Grant);
    let fixture = sealed(Some(&tsa));
    let server = start_server(&fixture);
    let reply = post(
        &server,
        "/v1/seal/notice",
        &fixture.token("render:seal", SEAL_CLIENT),
        "application/pdf",
    );
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(reply.header("content-type"), Some("application/pdf"));
    let expected = first_revision(&fixture);
    assert!(reply.body.starts_with(&expected.pdf));
    let signed_file_sha256 = sha256_hex(&reply.body);
    assert_eq!(
        reply.header("x-registry-document-sha256"),
        Some(expected.pdf_sha256.as_str())
    );
    assert_eq!(
        reply.header("x-registry-signed-file-sha256"),
        Some(signed_file_sha256.as_str())
    );
    assert_eq!(reply.header("x-registry-seal-id"), Some("ministry"));
    assert_eq!(reply.header("x-registry-seal-level"), Some("b-t"));
    assert!(reply.header("x-registry-certificate-sha256").is_some());
    assert!(reply.header("x-registry-timestamp-time").is_some());
    assert_eq!(reply.header("x-registry-warning-count"), Some("0"));
    assert_eq!(
        reply.header("x-registry-document-version"),
        Some("notice v2")
    );
    assert_eq!(
        reply.header("x-registry-bundle-hash"),
        Some(expected.bundle_hash.as_str())
    );
    assert!(reply.header("x-registry-pdf-sha256").is_none());
}

#[test]
fn a_b_b_seal_is_the_named_choice_and_carries_no_timestamp() {
    let fixture = sealed(None);
    let server = start_server(&fixture);
    let body = seal_json(&fixture, &server);
    assert_eq!(body["seal"]["level"], "b-b");
    assert!(body["seal"].get("timestampTime").is_none(), "{body}");
    let pdf = base64_decode(body["pdfBase64"].as_str().unwrap());
    let expected = first_revision(&fixture);
    assert!(pdf.starts_with(&expected.pdf));
    assert_eq!(body["documentSha256"], expected.pdf_sha256);
    assert_eq!(body["signedFileSha256"], sha256_hex(&pdf));
    let signed = read_signed_file(&pdf, expected.pdf.len());
    let parts = [
        signed.signed_parts[0].as_slice(),
        signed.signed_parts[1].as_slice(),
    ];
    let verified = verify_detached_signature(&signed.cms_der, &parts).expect("the CMS verifies");
    assert_eq!(verified.timestamp_gen_time, None);
    assert_eq!(
        body["seal"]["certificateSha256"],
        verified.signer_fingerprint.to_string()
    );
}

#[test]
fn the_signing_member_reaches_the_template_only_on_the_seal_route() {
    let tsa = start_tsa(TsaMode::Grant);
    let fixture = sealed(Some(&tsa));
    let server = start_server(&fixture);
    let sealed_body = seal_json(&fixture, &server);
    let sealed_envelope = PLAIN_ENVELOPE.replace(
        r#""labels":{}}"#,
        &format!(
            r#""labels":{{}},"signing":{{"mode":"seal","signerName":"{TEST_SEAL_ORGANIZATION}","testOnly":true}}}}"#
        ),
    );
    assert_eq!(
        sealed_body["dataSha256"],
        sha256_hex(sealed_envelope.as_bytes()),
        "the seal route's envelope carries the signing member, test flag set"
    );
    let plain = post(
        &server,
        "/v1/render/notice",
        &fixture.token("render:render", OTHER_CLIENT),
        "application/json",
    );
    assert_eq!(
        plain.status,
        200,
        "{}",
        String::from_utf8_lossy(&plain.body)
    );
    assert_eq!(
        plain.json()["dataSha256"],
        sha256_hex(PLAIN_ENVELOPE.as_bytes()),
        "the plain route's envelope has no signing member"
    );
}

#[test]
fn the_plain_route_returns_identical_bytes_with_and_without_signing() {
    let tsa = start_tsa(TsaMode::Grant);
    let with_signing = sealed(Some(&tsa));
    let without_signing = deployment(None);
    let mut bodies = Vec::new();
    for fixture in [&with_signing, &without_signing] {
        let server = start_server(fixture);
        let reply = post(
            &server,
            "/v1/render/notice",
            &fixture.token("render:render", OTHER_CLIENT),
            "application/pdf",
        );
        assert_eq!(
            reply.status,
            200,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        bodies.push(reply.body);
    }
    assert_eq!(bodies[0], bodies[1]);
    assert_eq!(
        tsa.requests.load(Ordering::SeqCst),
        0,
        "rendering never timestamps"
    );
}

#[test]
fn without_signing_the_seal_route_and_signing_readiness_do_not_exist() {
    let fixture = deployment(None);
    let server = start_server(&fixture);
    let reply = post(
        &server,
        "/v1/seal/notice",
        &fixture.token("render:seal", SEAL_CLIENT),
        "application/json",
    );
    assert_eq!(reply.status, 404);
    assert_eq!(reply.json()["code"], "render.not-found");
    let ready = request(server.port, "GET", "/ready", &[], None);
    assert_eq!(ready.status, 200);
    assert_eq!(ready.json(), serde_json::json!({"status":"ready"}));
    let openapi = request(server.port, "GET", "/openapi.json", &[], None).json();
    assert!(openapi["paths"].get("/v1/seal/{type}").is_none());
}

#[test]
fn readiness_reports_each_seal_and_never_requests_a_timestamp() {
    let tsa = start_tsa(TsaMode::Grant);
    let fixture = sealed(Some(&tsa));
    let server = start_server(&fixture);
    for _ in 0..3 {
        let ready = request(server.port, "GET", "/ready", &[], None);
        assert_eq!(ready.status, 200);
        assert_eq!(
            ready.json(),
            serde_json::json!({"status":"ready","signing":{"ministry":{"status":"ready","testOnly":true}}})
        );
    }
    assert_eq!(tsa.requests.load(Ordering::SeqCst), 0);
    let openapi = request(server.port, "GET", "/openapi.json", &[], None).json();
    let seal = &openapi["paths"]["/v1/seal/{type}"]["post"];
    assert!(seal["security"][0]["bearerAuth"].is_array());
    for status in ["200", "400", "401", "403", "502", "503"] {
        assert!(seal["responses"].get(status).is_some(), "{status}");
    }
}

#[test]
fn render_stays_ready_while_an_expired_seal_is_unavailable() {
    let tsa = start_tsa(TsaMode::Grant);
    let pki = seal_pki();
    let expired = pki
        .issue_seal_with(SigningAlgorithm::Es256, |params| {
            params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(30);
            params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        })
        .unwrap();
    let fixture = deployment(Some(SealSpec {
        tsa_url: Some(format!("http://127.0.0.1:{}/tsr", tsa.port)),
        seal: expired,
        key_of: None,
    }));
    let server = start_server(&fixture);
    let ready = request(server.port, "GET", "/ready", &[], None);
    assert_eq!(ready.status, 200, "render stays ready");
    assert_eq!(
        ready.json(),
        serde_json::json!({"status":"ready","signing":{"ministry":{"status":"unavailable","reason":"certificate-expired","testOnly":true}}})
    );
    let plain = post(
        &server,
        "/v1/render/notice",
        &fixture.token("render:render", OTHER_CLIENT),
        "application/pdf",
    );
    assert_eq!(plain.status, 200);
    let refused = post(
        &server,
        "/v1/seal/notice",
        &fixture.token("render:seal", SEAL_CLIENT),
        "application/json",
    );
    assert_eq!(refused.status, 503);
    let problem = refused.json();
    assert_eq!(problem["code"], "render.seal-certificate-invalid");
    assert_eq!(
        problem["type"],
        "https://render.registrystack.org/problems/seal-certificate-invalid"
    );
    assert!(problem["detail"].as_str().unwrap().contains("expired"));
    assert_eq!(tsa.requests.load(Ordering::SeqCst), 0);
}

/// The startup warnings `serve` logs about seal `ministry`, by message.
fn seal_startup_warnings(server: &Server, message: &str) -> Vec<serde_json::Value> {
    server
        .log()
        .into_iter()
        .filter(|line| {
            line["level"] == "WARN"
                && line["fields"]["seal_id"] == "ministry"
                && line["fields"]["message"] == message
        })
        .collect()
}

#[test]
fn serve_warns_at_startup_about_a_seal_that_cannot_sign_or_expires_soon() {
    let pki = seal_pki();
    let deployment_with = |not_before_days: i64, not_after_days: i64| {
        let seal = pki
            .issue_seal_with(SigningAlgorithm::Es256, |params| {
                let now = time::OffsetDateTime::now_utc();
                params.not_before = now + time::Duration::days(not_before_days);
                params.not_after = now + time::Duration::days(not_after_days);
            })
            .unwrap();
        deployment(Some(SealSpec {
            tsa_url: None,
            seal,
            key_of: None,
        }))
    };
    for (fixture, reason) in [
        (deployment_with(-30, -1), "certificate-expired"),
        (deployment_with(2, 400), "certificate-not-yet-valid"),
    ] {
        let server = start_server(&fixture);
        let unavailable = seal_startup_warnings(&server, "seal unavailable");
        assert_eq!(unavailable.len(), 1, "{reason}");
        assert_eq!(unavailable[0]["fields"]["reason"], reason);
        assert!(seal_startup_warnings(&server, "seal certificate expiring").is_empty());
    }

    let expiring = deployment_with(-30, 10);
    let server = start_server(&expiring);
    assert_eq!(
        seal_startup_warnings(&server, "seal certificate expiring").len(),
        1
    );
    assert!(seal_startup_warnings(&server, "seal unavailable").is_empty());

    let healthy = deployment_with(-1, 400);
    let server = start_server(&healthy);
    assert!(seal_startup_warnings(&server, "seal unavailable").is_empty());
    assert!(seal_startup_warnings(&server, "seal certificate expiring").is_empty());
}

#[test]
fn each_authorization_refusal_has_its_own_problem() {
    let tsa = start_tsa(TsaMode::Grant);
    let fixture = sealed(Some(&tsa));
    let server = start_server(&fixture);
    let cases = [
        (
            fixture.token("render:render", SEAL_CLIENT),
            "/v1/seal/notice",
            403,
            "render.forbidden",
            "render:seal",
        ),
        (
            fixture.token("render:seal", SEAL_CLIENT),
            "/v1/render/notice",
            403,
            "render.forbidden",
            "render:render",
        ),
        (
            fixture.token("render:seal", OTHER_CLIENT),
            "/v1/seal/notice",
            403,
            "render.seal-client-not-allowed",
            "not allowed",
        ),
        (
            fixture.token("render:seal", SEAL_CLIENT),
            "/v1/seal/letter",
            400,
            "render.document-not-sealable",
            "declares no seal",
        ),
        (
            fixture.token("render:seal", SEAL_CLIENT),
            "/v1/seal/missing",
            400,
            "render.unknown-document",
            "",
        ),
    ];
    for (token, route, status, code, guidance) in cases {
        let reply = post(&server, route, &token, "application/json");
        assert_eq!(reply.status, status, "{route} {code}");
        let problem = reply.json();
        assert_eq!(problem["code"], code, "{problem}");
        assert!(
            problem["detail"].as_str().unwrap().contains(guidance),
            "{problem}"
        );
    }
    assert_eq!(
        tsa.requests.load(Ordering::SeqCst),
        0,
        "no refusal reaches the authority"
    );
    drop(server);
    let audit = fixture.audit();
    let refused: Vec<&str> = audit
        .iter()
        .filter_map(|entry| entry["record"]["problem"].as_str())
        .collect();
    assert_eq!(
        refused,
        [
            "forbidden",
            "forbidden",
            "seal-client-not-allowed",
            "document-not-sealable",
            "unknown-document"
        ]
    );
}

#[test]
fn the_legacy_api_key_never_seals() {
    let pki = seal_pki();
    let fixture = deployment(Some(SealSpec {
        tsa_url: None,
        seal: pki.issue_seal(SigningAlgorithm::Es256).unwrap(),
        key_of: None,
    }));
    write_secret(
        &fixture.home.join("api.key"),
        "test-key-0123456789abcdef0123456789abcdef",
    );
    let text = std::fs::read_to_string(&fixture.runtime_path).unwrap();
    let start = text.find("  oidc:").unwrap();
    let end = text.find(LIMITS).unwrap();
    let text = format!(
        "{}  apiKeyRef: secret:file/api.key\n{}",
        &text[..start],
        &text[end..]
    );
    std::fs::write(&fixture.runtime_path, text).unwrap();
    let (code, stderr) = refused_startup(&fixture);
    assert_eq!(
        code,
        Some(registry_render::ProblemKind::RuntimeInvalid.exit_code()),
        "{stderr}"
    );
    assert!(
        stderr.contains("render.runtime.signing-requires-oidc"),
        "{stderr}"
    );
}

#[test]
fn a_key_that_does_not_match_its_certificate_refuses_startup_by_position() {
    let pki = seal_pki();
    let fixture = deployment(Some(SealSpec {
        tsa_url: None,
        seal: pki.issue_seal(SigningAlgorithm::Es256).unwrap(),
        key_of: Some(pki.issue_seal(SigningAlgorithm::Es256).unwrap()),
    }));
    let (code, stderr) = refused_startup(&fixture);
    assert_eq!(
        code,
        Some(registry_render::ProblemKind::SealCertificateInvalid.exit_code()),
        "{stderr}"
    );
    assert!(
        stderr.contains("render.runtime.seal-key-mismatch"),
        "{stderr}"
    );
    assert!(
        stderr.contains("/signing/seals/ministry/privateKeyRef"),
        "{stderr}"
    );
    for value in [TEST_SEAL_ORGANIZATION, "Registry Stack Test Seal"] {
        assert!(!stderr.contains(value), "no certificate subject: {stderr}");
    }
}

#[test]
fn an_unreadable_or_invalid_chain_refuses_startup_by_position() {
    let pki = seal_pki();
    let fixture = deployment(Some(SealSpec {
        tsa_url: None,
        seal: pki.issue_seal(SigningAlgorithm::Es256).unwrap(),
        key_of: None,
    }));
    std::fs::write(fixture.home.join("chain.pem"), "not a certificate\n").unwrap();
    let (code, stderr) = refused_startup(&fixture);
    assert_eq!(
        code,
        Some(registry_render::ProblemKind::SealCertificateInvalid.exit_code()),
        "{stderr}"
    );
    assert!(
        stderr.contains("render.runtime.seal-chain-invalid"),
        "{stderr}"
    );
    assert!(
        stderr.contains("/signing/seals/ministry/certificateChainFile"),
        "{stderr}"
    );
    std::fs::remove_file(fixture.home.join("chain.pem")).unwrap();
    let (code, stderr) = refused_startup(&fixture);
    assert_eq!(
        code,
        Some(registry_render::ProblemKind::SealCertificateInvalid.exit_code()),
        "{stderr}"
    );
    assert!(
        stderr.contains("render.runtime.seal-chain-unreadable"),
        "{stderr}"
    );
    assert!(
        !stderr.contains(&fixture.home.display().to_string()),
        "the message repeats no path: {stderr}"
    );
}

#[test]
fn a_certificate_without_a_signing_key_usage_refuses_startup() {
    let pki = seal_pki();
    let seal = pki
        .issue_seal_with(SigningAlgorithm::Es256, |params| {
            params.key_usages = vec![rcgen::KeyUsagePurpose::KeyEncipherment];
        })
        .unwrap();
    let fixture = deployment(Some(SealSpec {
        tsa_url: None,
        seal,
        key_of: None,
    }));
    let (code, stderr) = refused_startup(&fixture);
    assert_eq!(
        code,
        Some(registry_render::ProblemKind::SealCertificateInvalid.exit_code()),
        "{stderr}"
    );
    assert!(
        stderr.contains("render.runtime.seal-certificate-usage"),
        "{stderr}"
    );
}

#[test]
fn a_failing_timestamp_authority_fails_the_seal_naming_the_piece() {
    // A port nothing listens on: the connection is refused.
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let cases: [(Option<TsaMode>, &str, &str); 7] = [
        (None, "could not be reached", "connection-failed"),
        (Some(TsaMode::Silent), "could not be reached", "timed-out"),
        (Some(TsaMode::Reject), "refused", "not-granted"),
        (Some(TsaMode::ServerError), "refused", "http-status"),
        (
            Some(TsaMode::Garbage),
            "invalid timestamp token",
            "malformed-response",
        ),
        (
            Some(TsaMode::Unbound),
            "invalid timestamp token",
            "tsa-certificate-not-named-by-token",
        ),
        (Some(TsaMode::Oversize), "too large", "response-too-large"),
    ];
    for (mode, piece, reason) in cases {
        let tsa = mode.map(start_tsa);
        let url = match &tsa {
            Some(tsa) => format!("http://127.0.0.1:{}/tsr", tsa.port),
            None => format!("http://127.0.0.1:{closed}/tsr"),
        };
        let pki = seal_pki();
        let fixture = deployment(Some(SealSpec {
            tsa_url: Some(url),
            seal: pki.issue_seal(SigningAlgorithm::Es256).unwrap(),
            key_of: None,
        }));
        let server = start_server(&fixture);
        let started = Instant::now();
        let reply = post(
            &server,
            "/v1/seal/notice",
            &fixture.token("render:seal", SEAL_CLIENT),
            "application/json",
        );
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "{piece}: the attempt timeout (2s) bounds the call"
        );
        assert_eq!(
            reply.status,
            502,
            "{piece}: {}",
            String::from_utf8_lossy(&reply.body)
        );
        let problem = reply.json();
        assert_eq!(problem["code"], "render.timestamp-failed");
        assert!(
            problem["detail"].as_str().unwrap().contains(piece),
            "{piece}: {problem}"
        );
        assert!(problem.get("pdfBase64").is_none());
        // The prepared file, its signature space still empty, never leaves:
        // under PDF/A-2 and PDF/A-3 it would not even be conformant.
        assert_eq!(
            reply.header("content-type"),
            Some("application/problem+json"),
            "{piece}"
        );
        assert!(find(&reply.body, b"%PDF").is_none(), "{piece}");
        if let Some(tsa) = &tsa {
            assert_eq!(tsa.requests.load(Ordering::SeqCst), 1, "{piece}: no retry");
        }
        // The operator reads the cause, value-free, in one log line.
        let log = server.log();
        let named: Vec<_> = log
            .iter()
            .filter(|line| line["fields"]["reason"] == reason)
            .collect();
        assert_eq!(named.len(), 1, "{reason}: {log:?}");
        assert_eq!(named[0]["level"], "WARN", "{reason}");
        assert_eq!(named[0]["fields"]["seal_id"], "ministry", "{reason}");
        assert_eq!(
            named[0]["fields"]["problem"], "timestamp-failed",
            "{reason}"
        );
        drop(server);
        let audit = fixture.audit();
        assert_eq!(audit.len(), 2, "{audit:?}");
        assert_eq!(audit[0]["phase"], "request");
        assert_eq!(audit[1]["phase"], "response");
        assert_eq!(audit[0]["correlation"], audit[1]["correlation"]);
        assert_eq!(audit[1]["record"]["outcome"], "refused");
        assert_eq!(audit[1]["record"]["problem"], "timestamp-failed");
        assert_eq!(audit[1]["record"]["reason"], reason, "{audit:?}");
        assert!(audit[0]["record"].get("reason").is_none());
        assert!(audit[1]["record"].get("signedFileSha256").is_none());
    }
}

#[test]
fn a_seal_writes_a_paired_value_free_audit() {
    let tsa = start_tsa(TsaMode::Grant);
    let fixture = sealed(Some(&tsa));
    let server = start_server(&fixture);
    let token = fixture.token("render:seal", SEAL_CLIENT);
    let body = seal_json(&fixture, &server);
    drop(server);
    let audit = fixture.audit();
    assert_eq!(audit.len(), 2, "{audit:?}");
    let (request_entry, response_entry) = (&audit[0], &audit[1]);
    assert_eq!(request_entry["phase"], "request");
    assert_eq!(response_entry["phase"], "response");
    assert_eq!(request_entry["correlation"], response_entry["correlation"]);
    assert_eq!(request_entry["record"]["sealId"], "ministry");
    assert!(request_entry["record"].get("outcome").is_none());
    for field in [
        "signedFileSha256",
        "certificateSha256",
        "timestampTokenSha256",
        "documentSha256",
    ] {
        assert!(
            request_entry["record"].get(field).is_none(),
            "{field} is a response value: {request_entry}"
        );
    }
    let record = &response_entry["record"];
    assert_eq!(record["outcome"], "sealed");
    assert_eq!(record["sealId"], "ministry");
    assert_eq!(record["documentSha256"], body["documentSha256"]);
    assert_eq!(record["signedFileSha256"], body["signedFileSha256"]);
    assert_eq!(
        record["certificateSha256"],
        body["seal"]["certificateSha256"]
    );
    assert_eq!(record["dataSha256"], body["dataSha256"]);
    assert_eq!(
        record["timestampTokenSha256"].as_str().map(str::len),
        Some(64)
    );
    assert!(record.get("pdfSha256").is_none(), "{record}");
    let text = std::fs::read_to_string(fixture.home.join("audit/render.jsonl")).unwrap();
    for protected in [
        TEST_SEAL_ORGANIZATION,
        "Registry Stack Test Seal",
        SEAL_CLIENT,
        "canary-principal",
        "issuer.example.test",
        token.as_str(),
    ] {
        assert!(!text.contains(protected), "audit holds no {protected}");
    }
}

/// What a running seal says about its trust: the JSON `seal` member, the
/// PDF header, the `/ready` entry, every audit entry of the call and the
/// startup warnings naming the seal.
struct TrustSignals {
    json: serde_json::Value,
    header: Option<String>,
    ready: serde_json::Value,
    audit: Vec<serde_json::Value>,
    startup_warnings: usize,
}

fn trust_signals(fixture: &Fixture) -> TrustSignals {
    let server = start_server(fixture);
    let token = fixture.token("render:seal", SEAL_CLIENT);
    let json = seal_json(fixture, &server)["seal"].clone();
    let reply = post(&server, "/v1/seal/notice", &token, "application/pdf");
    assert_eq!(reply.status, 200);
    let header = reply.header("x-registry-seal-test-only").map(str::to_owned);
    let ready =
        request(server.port, "GET", "/ready", &[], None).json()["signing"]["ministry"].clone();
    let startup_warnings = server
        .log()
        .iter()
        .filter(|line| {
            line["level"] == "WARN"
                && line["fields"]["seal_id"] == "ministry"
                && line["fields"]["message"] == "test-only seal: its documents are not official"
        })
        .count();
    drop(server);
    let audit = fixture
        .audit()
        .into_iter()
        .map(|entry| entry["record"].clone())
        .collect();
    TrustSignals {
        json,
        header,
        ready,
        audit,
        startup_warnings,
    }
}

#[test]
fn a_test_only_seal_says_so_in_every_answer_and_a_production_seal_adds_nothing() {
    let fixture = sealed(None);
    let test_only = trust_signals(&fixture);
    assert_eq!(test_only.json["testOnly"], true, "{}", test_only.json);
    assert_eq!(test_only.header.as_deref(), Some("true"));
    assert_eq!(
        test_only.ready,
        serde_json::json!({"status": "ready", "testOnly": true})
    );
    assert_eq!(test_only.audit.len(), 4, "two calls, paired");
    for record in &test_only.audit {
        assert_eq!(record["testOnly"], true, "{record}");
    }
    assert_eq!(test_only.startup_warnings, 1);

    // The same seal without `trust` is a production seal.
    let text = std::fs::read_to_string(&fixture.runtime_path).unwrap();
    let production = text.replacen("      trust: test-only\n", "", 1);
    assert_ne!(production, text);
    std::fs::write(&fixture.runtime_path, production).unwrap();
    std::fs::write(fixture.home.join("audit/render.jsonl"), "").unwrap();
    let production = trust_signals(&fixture);
    assert!(
        production.json.get("testOnly").is_none(),
        "{}",
        production.json
    );
    assert_eq!(production.header, None);
    assert_eq!(production.ready, serde_json::json!({"status": "ready"}));
    assert_eq!(production.audit.len(), 4);
    for record in &production.audit {
        assert!(record.get("testOnly").is_none(), "{record}");
    }
    assert_eq!(production.startup_warnings, 0);
}

#[test]
fn a_chain_too_large_for_the_reserved_space_refuses_startup() {
    let pki = seal_pki();
    let seal = pki
        .issue_seal_with(SigningAlgorithm::Es256, |params| {
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 55555, 1],
                    vec![0x5a; 256 * 1024],
                ));
        })
        .unwrap();
    let fixture = deployment(Some(SealSpec {
        tsa_url: None,
        seal,
        key_of: None,
    }));
    let (code, stderr) = refused_startup(&fixture);
    assert_eq!(
        code,
        Some(registry_render::ProblemKind::SealCertificateInvalid.exit_code()),
        "{stderr}"
    );
    assert!(
        stderr.contains("render.runtime.seal-chain-too-large"),
        "{stderr}"
    );
    assert!(
        stderr.contains("/signing/seals/ministry/certificateChainFile"),
        "{stderr}"
    );
}

#[test]
fn a_pdf_a_2_document_seals_within_its_string_limit() {
    let tsa = start_tsa(TsaMode::Grant);
    let fixture = sealed(Some(&tsa));
    let server = start_server(&fixture);
    let reply = post(
        &server,
        "/v1/seal/archive",
        &fixture.token("render:seal", SEAL_CLIENT),
        "application/json",
    );
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let body = reply.json();
    assert_eq!(body["seal"]["level"], "b-t");
    let pdf = base64_decode(body["pdfBase64"].as_str().unwrap());
    let expected = first_revision_of(&fixture, "archive");
    assert!(
        pdf.starts_with(&expected.pdf),
        "the sealed file starts with the exact first revision"
    );
    let signed = read_signed_file(&pdf, expected.pdf.len());
    assert!(
        signed.reserved <= 32_767,
        "a typical B-T seal fits a PDF/A-2 string: {} bytes",
        signed.reserved
    );
    let parts = [
        signed.signed_parts[0].as_slice(),
        signed.signed_parts[1].as_slice(),
    ];
    let verified = verify_detached_signature(&signed.cms_der, &parts).expect("the CMS verifies");
    assert!(
        verified.timestamp_gen_time.is_some(),
        "B-T carries a timestamp"
    );
}

#[test]
fn a_seal_too_large_for_a_document_pdf_standard_refuses_startup() {
    // A B-T seal whose chain makes it reserve about 37 KB: within what a
    // field may reserve, beyond what the PDF/A-2b `archive` can hold.
    let pki = seal_pki();
    let seal = pki
        .issue_seal_with(SigningAlgorithm::Es256, |params| {
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 55555, 1],
                    vec![0x5a; 16 * 1024],
                ));
        })
        .unwrap();
    let fixture = deployment(Some(SealSpec {
        tsa_url: Some("http://127.0.0.1:9/tsr".to_owned()),
        seal,
        key_of: None,
    }));
    let (code, stderr) = refused_startup(&fixture);
    assert_eq!(
        code,
        Some(registry_render::ProblemKind::RuntimeInvalid.exit_code()),
        "{stderr}"
    );
    assert!(
        stderr.contains("render.bundle.seal-space-exceeds-standard"),
        "{stderr}"
    );
    assert!(stderr.contains("/documents/2/seal"), "{stderr}");
    assert!(
        stderr.contains("PDF/A-2 and PDF/A-3 limit a string to 32767 bytes"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("/documents/0/seal"),
        "the plain notice keeps its seal: {stderr}"
    );
}

/// Write sealed files served by the seal route for an external validator
/// such as `products/render/scripts/validate-seal.py`: a B-T and a B-B
/// notice, a B-T PDF/A-2b archive and a B-T PDF/UA-1 notice, each with its
/// `documentSha256`, and the seal and timestamp trust roots. Run it with
/// `REGISTRY_SEAL_SAMPLE_DIR` naming an existing directory.
#[test]
#[ignore = "writes served seal samples to REGISTRY_SEAL_SAMPLE_DIR"]
fn write_served_seal_samples() {
    let dir = PathBuf::from(
        std::env::var_os("REGISTRY_SEAL_SAMPLE_DIR").expect("REGISTRY_SEAL_SAMPLE_DIR is set"),
    );
    let tsa = start_tsa(TsaMode::Grant);
    let pki = seal_pki();
    std::fs::write(dir.join("seal-root.pem"), pki.root_certificate_pem()).unwrap();
    std::fs::write(dir.join("tsa-root.pem"), &tsa.root_pem).unwrap();
    let timestamped = sealed_by(&pki, Some(&tsa));
    let untimestamped = sealed_by(&pki, None);
    for (name, fixture, document) in [
        ("notice-b-t", &timestamped, "notice"),
        ("archive-b-t", &timestamped, "archive"),
        ("accessible-b-t", &timestamped, "accessible"),
        ("notice-b-b", &untimestamped, "notice"),
    ] {
        let server = start_server(fixture);
        let reply = post(
            &server,
            &format!("/v1/seal/{document}"),
            &fixture.token("render:seal", SEAL_CLIENT),
            "application/json",
        );
        assert_eq!(
            reply.status,
            200,
            "{name}: {}",
            String::from_utf8_lossy(&reply.body)
        );
        let body = reply.json();
        let pdf = base64_decode(body["pdfBase64"].as_str().expect("pdfBase64"));
        std::fs::write(dir.join(format!("{name}.pdf")), &pdf).unwrap();
        std::fs::write(
            dir.join(format!("{name}.document-sha256")),
            body["documentSha256"].as_str().expect("documentSha256"),
        )
        .unwrap();
    }
}
