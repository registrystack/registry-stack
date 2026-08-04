//! `mint token` against a real `mint serve`, as two processes.
//!
//! The point of the subcommand is that it is an ordinary client: it proves who
//! it is and the endpoint decides. Testing it at the process boundary is what
//! shows that. It also pins the output contract the subcommand exists for, that
//! stdout carries the access token and nothing else, which no in-process test
//! of the builder could observe.

use std::{
    fs,
    io::ErrorKind,
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

const ISSUER: &str = "https://mint.example.org";
const ASSERTION_AUDIENCE: &str = "https://mint.example.org/token";
const ACTOR: &str = "urn:example:agent:scheduler";

/// Deterministic Ed25519 material, so a test knows which identity signed what.
fn key_pair(seed: u8) -> (Value, Value) {
    let seed_bytes = [seed; 32];
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
    let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
    let kid = format!("key-{seed}");
    (
        json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x}),
        json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x,
               "d": URL_SAFE_NO_PAD.encode(seed_bytes)}),
    )
}

/// A running `mint serve`, killed when the test drops it however it ends.
struct Server {
    _directory: tempfile::TempDir,
    child: Child,
    port: u16,
    root: PathBuf,
    config: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    fn token_url(&self) -> String {
        format!("http://127.0.0.1:{}/token", self.port)
    }

    fn caller_key(&self, client_id: &str) -> PathBuf {
        self.root.join(format!("{client_id}.jwk"))
    }
}

fn write_owner_only(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write secret");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("restrict secret");
}

/// Write a deployment, start the binary on it, and wait for the listener.
fn server() -> Server {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path().to_path_buf();
    fs::create_dir(root.join("secrets")).expect("create secrets directory");
    fs::create_dir(root.join("clients")).expect("create clients directory");

    let (_, signing_private) = key_pair(9);
    write_owner_only(
        &root.join("secrets/signing.jwk"),
        &signing_private.to_string(),
    );
    write_owner_only(
        &root.join("secrets/audit-hmac-key"),
        "0123456789abcdef0123456789abcdef",
    );

    // `listener.port: 0` would leave the test unable to find the port, so an
    // ephemeral one is reserved and released. The window is a test-only risk.
    let port = TcpListener::bind("127.0.0.1:0")
        .expect("reserve a port")
        .local_addr()
        .expect("the reserved port")
        .port();

    let (scheduler_public, scheduler_private) = key_pair(1);
    write_owner_only(&root.join("scheduler.jwk"), &scheduler_private.to_string());
    fs::write(
        root.join("clients/scheduler.yaml"),
        format!(
            "clientId: scheduler
principal: urn:example:principal:scheduler
evidenceAudience: https://scheduler.example.org
requesterTags: [scheduler]
keys: [{scheduler_public}]
delegation:
  actors: [{ACTOR}]
  subjectClaims:
    given_name: identity.given_name
    birth_date: identity.birth_date
"
        ),
    )
    .expect("write scheduler registration");

    let (reporter_public, reporter_private) = key_pair(2);
    write_owner_only(&root.join("reporter.jwk"), &reporter_private.to_string());
    fs::write(
        root.join("clients/reporter.yaml"),
        format!(
            "clientId: reporter
principal: urn:example:principal:reporter
evidenceAudience: https://reporter.example.org
requesterTags: [reporter]
keys: [{reporter_public}]
"
        ),
    )
    .expect("write reporter registration");

    let config = root.join("mint.yaml");
    fs::write(
        &config,
        format!(
            "version: 1
issuer: {ISSUER}
listener: {{address: 127.0.0.1, port: {port}}}
signing:
  algorithm: EdDSA
  activeKeyId: key-9
  activeKeyFile: secrets/signing.jwk
audit:
  path: audit/mint.jsonl
  hashKeyFile: secrets/audit-hmac-key
  hashKeyVersion: 1
accessTokens:
  audiences: [evidence.example.org]
  lifetimeSeconds: 300
  claims:
    principal: sub
    requesterTags: evidence_tags
    evidenceAudience: evidence_audience
    grantId: evidence_grant_id
    grantAuthority: evidence_authority
    actor: evidence_actor
clientAssertion:
  audience: {ASSERTION_AUDIENCE}
  algorithms: [EdDSA]
clients:
  directory: clients
"
        ),
    )
    .expect("write config");

    let child = Command::new(env!("CARGO_BIN_EXE_mint"))
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the mint binary starts");

    let server = Server {
        _directory: directory,
        child,
        port,
        root,
        config,
    };
    wait_for_listener(port);
    server
}

fn wait_for_listener(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(_) => return,
            Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
                assert!(
                    Instant::now() < deadline,
                    "the token endpoint never accepted"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => panic!("the token endpoint could not be reached: {error}"),
        }
    }
}

fn mint_token(server: &Server, client_id: &str, extra: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mint"));
    command
        .arg("token")
        .arg("--url")
        .arg(server.token_url())
        // The endpoint is reached over loopback but its configured assertion
        // audience is its public URL, which is the deployment shape behind a
        // TLS terminator and the reason the flag exists.
        .arg("--audience")
        .arg(ASSERTION_AUDIENCE)
        .arg("--client-id")
        .arg(client_id)
        .arg("--key")
        .arg(server.caller_key(client_id))
        .args(extra);
    command.output().expect("the mint binary runs")
}

fn claims_of(token: &str) -> Value {
    let segments: Vec<&str> = token.split('.').collect();
    assert_eq!(segments.len(), 3, "an access token has three segments");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).expect("base64url"))
        .expect("claims parse")
}

fn stdout_of(output: &Output) -> String {
    assert!(
        output.status.success(),
        "the command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

#[test]
fn the_subcommand_obtains_a_token_the_endpoint_agreed_to_issue() {
    let server = server();
    let output = mint_token(&server, "reporter", &[]);
    let stdout = stdout_of(&output);

    // Exactly one line, so `TOKEN=$(mint token ...)` is the whole usage.
    assert_eq!(stdout.lines().count(), 1, "stdout was: {stdout:?}");
    let claims = claims_of(stdout.trim());

    assert_eq!(claims["iss"], json!(ISSUER));
    assert_eq!(claims["sub"], json!("urn:example:principal:reporter"));
    assert_eq!(claims["client_id"], json!("reporter"));
    assert_eq!(claims["evidence_tags"], json!(["reporter"]));
    assert_eq!(
        claims["evidence_audience"],
        json!("https://reporter.example.org")
    );
    // The authority came from the registry, not from anything the caller sent.
    assert!(claims.get("evidence_actor").is_none());

    let verification = Command::new(env!("CARGO_BIN_EXE_mint"))
        .arg("verify-audit")
        .arg("--config")
        .arg(&server.config)
        .output()
        .expect("the verifier runs");
    assert!(verification.status.success());
    assert!(String::from_utf8_lossy(&verification.stdout).contains("records=1"));
}

#[test]
fn a_delegated_token_carries_the_actor_and_the_subject_from_the_registry_paths() {
    let server = server();
    let subject = server.root.join("subject.json");
    fs::write(
        &subject,
        json!({"given_name": "Amara", "birth_date": "1998-04-02"}).to_string(),
    )
    .expect("write subject file");

    let output = mint_token(
        &server,
        "scheduler",
        &[
            "--actor",
            ACTOR,
            "--subject-file",
            subject.to_str().expect("a UTF-8 path"),
        ],
    );
    let claims = claims_of(stdout_of(&output).trim());

    assert_eq!(claims["evidence_actor"], json!(ACTOR));
    assert_eq!(
        claims["identity"],
        json!({"given_name": "Amara", "birth_date": "1998-04-02"}),
        "the claim paths are the registry's, not the request's"
    );
}

/// The subcommand authenticates; it does not decide. An actor the registration
/// does not permit must be refused by the endpoint, with no token printed.
#[test]
fn an_unregistered_actor_is_refused_by_the_endpoint() {
    let server = server();
    let subject = server.root.join("other-subject.json");
    fs::write(
        &subject,
        json!({"given_name": "Amara", "birth_date": "1998-04-02"}).to_string(),
    )
    .expect("write subject file");

    let output = mint_token(
        &server,
        "scheduler",
        &[
            "--actor",
            "urn:example:agent:not-registered",
            "--subject-file",
            subject.to_str().expect("a UTF-8 path"),
        ],
    );

    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "a refusal must print no token: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid_client"),
        "the refusal should be reported: {stderr}"
    );
}

/// A subject file that is not a flat object of scalars is a caller mistake with
/// an opaque server-side answer, so it is named locally instead.
#[test]
fn a_malformed_subject_file_is_refused_before_the_request() {
    let server = server();
    let subject = server.root.join("nested-subject.json");
    fs::write(
        &subject,
        json!({"identity": {"given_name": "Amara"}}).to_string(),
    )
    .expect("write subject file");

    let output = mint_token(
        &server,
        "scheduler",
        &[
            "--actor",
            ACTOR,
            "--subject-file",
            subject.to_str().expect("a UTF-8 path"),
        ],
    );

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must be a scalar value"),
        "the mistake should be named: {stderr}"
    );
}

/// A key file anyone else can read is a key that should be assumed leaked.
#[test]
fn a_group_readable_client_key_is_refused() {
    let server = server();
    let key = server.caller_key("reporter");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("loosen the key file");

    let output = mint_token(&server, "reporter", &[]);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("client key could not be read"),
        "the refusal should name the key file: {stderr}"
    );
}
