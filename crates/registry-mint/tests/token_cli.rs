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
use registry_platform_crypto::PublicJwk;
use serde_json::{json, Value};

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

fn service_key_pair(seed: u8) -> (Value, Value) {
    let scalar = [seed; 32];
    let signing = p256::ecdsa::SigningKey::from_slice(&scalar).expect("valid P-256 scalar");
    let encoded = signing.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded.x().expect("uncompressed x"));
    let y = URL_SAFE_NO_PAD.encode(encoded.y().expect("uncompressed y"));
    let bare = PublicJwk::parse(
        &json!({"kty":"EC", "crv":"P-256", "alg":"ES256", "x":x, "y":y}).to_string(),
    )
    .expect("public JWK parses");
    let kid = bare.jkt().expect("thumbprint computes");
    (
        json!({"kty":"EC", "crv":"P-256", "alg":"ES256", "kid":kid, "x":x, "y":y}),
        json!({"kty":"EC", "crv":"P-256", "alg":"ES256", "kid":kid, "x":x, "y":y, "d":URL_SAFE_NO_PAD.encode(scalar)}),
    )
}

/// A running `mint serve`, killed when the test drops it however it ends.
struct Server {
    _directory: tempfile::TempDir,
    child: Child,
    port: u16,
    root: PathBuf,
    config: PathBuf,
    issuer: String,
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

    fn assertion_audience(&self) -> String {
        format!("{}/token", self.issuer)
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
    fs::create_dir(root.join("public-keys")).expect("create public key directory");

    let (signing_public, signing_private) = service_key_pair(9);
    let public_file = format!(
        "{}.jwk.json",
        signing_public["kid"].as_str().expect("service key id")
    );
    fs::write(
        root.join("public-keys").join(&public_file),
        signing_public.to_string(),
    )
    .expect("write governed public key");
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
    let issuer = format!("http://127.0.0.1:{port}");
    let assertion_audience = format!("{issuer}/token");

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
validationMode: supervised-local-development
issuer: {issuer}
listener: {{address: 127.0.0.1, port: {port}}}
signing:
  algorithm: ES256
  activePublicJwkFile: public-keys/{public_file}
  publishedPublicJwkFiles: []
  revokedKeyIds: []
signer:
  kind: local-jwk
  privateKeyRef: secret:file/signing.jwk
secretProviders:
  file: {{root: {}}}
audit:
  path: audit/mint.jsonl
  maximumFileBytes: 1073741824
  hashKeyRef: secret:file/audit-hmac-key
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
  audience: {assertion_audience}
  algorithms: [EdDSA]
clients:
  directory: clients
",
            root.join("secrets").display()
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
        issuer,
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
        .arg(server.assertion_audience())
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

    assert_eq!(claims["iss"], json!(server.issuer));
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
    let verification = String::from_utf8_lossy(&verification.stdout);
    assert!(verification.contains("active-segment: not verified"));
}

#[test]
fn the_configuration_check_runs_against_a_deployment_that_is_already_serving() {
    // The whole point of `mint check` is to read a configuration before
    // restarting the service that is running on it. One writer holds the audit
    // chain for the life of the serving process, so a check that took the
    // writer would report every live deployment as broken.
    let server = server();
    let output = Command::new(env!("CARGO_BIN_EXE_mint"))
        .arg("check")
        .arg("--config")
        .arg(&server.config)
        .output()
        .expect("the checker runs");

    assert!(
        output.status.success(),
        "check failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_runtime_dependency_check_claims_the_audit_writer_before_startup() {
    let server = server();
    let output = Command::new(env!("CARGO_BIN_EXE_mint"))
        .arg("check")
        .arg("--config")
        .arg(&server.config)
        .arg("--require-runtime-dependencies")
        .output()
        .expect("the checker runs");

    assert!(
        !output.status.success(),
        "a full dependency preflight must not claim a live writer's audit chain"
    );
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!diagnostics.contains("0123456789abcdef"));
}

/// Run the full dependency preflight and additionally require the configured
/// audit sink to resolve inside `root`, the path an operator declares persistent.
fn check_audit_under(server: &Server, root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mint"))
        .arg("check")
        .arg("--config")
        .arg(&server.config)
        .arg("--require-runtime-dependencies")
        .arg("--require-audit-under")
        .arg(root)
        .output()
        .expect("the checker runs")
}

/// Stop the staged deployment so the dependency preflight can claim the writer.
fn stopped_server() -> Server {
    let mut server = server();
    server.child.kill().expect("stop the serving process");
    server.child.wait().expect("reap the serving process");
    server
}

#[test]
fn the_dependency_check_accepts_an_audit_sink_inside_the_required_root() {
    // `audit.path` is configured relative to the configuration file, so passing
    // against the configuration directory is what proves Mint compared the
    // destination its own configuration contract resolved.
    let server = stopped_server();

    let output = check_audit_under(&server, &server.root);

    assert!(
        output.status.success(),
        "check failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_dependency_check_refuses_an_audit_sink_outside_the_required_root() {
    let ephemeral = tempfile::tempdir().expect("temp dir");
    let server = stopped_server();

    let output = check_audit_under(&server, ephemeral.path());

    assert!(
        !output.status.success(),
        "an audit sink outside the declared root must fail closed"
    );
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(diagnostics
        .contains("the configured audit destination resolves outside the declared audit root"));
    assert!(!diagnostics.contains(&server.root.join("audit/mint.jsonl").display().to_string()));
    assert!(!diagnostics.contains("0123456789abcdef"));
}

#[test]
fn the_dependency_check_refuses_an_audit_directory_symlinked_out_of_the_required_root() {
    // The decoy: durable storage really is mounted at the declared root, and
    // the configured path really does sit inside it, but the chain lands on
    // storage that disappears with the container.
    let ephemeral = tempfile::tempdir().expect("temp dir");
    let server = stopped_server();
    fs::remove_dir_all(server.root.join("audit")).expect("remove the staged audit directory");
    std::os::unix::fs::symlink(ephemeral.path(), server.root.join("audit"))
        .expect("plant an escaping audit directory");

    let output = check_audit_under(&server, &server.root);

    assert!(
        !output.status.success(),
        "a symlink must not carry the audit chain out of the declared root"
    );
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(diagnostics
        .contains("the configured audit destination resolves outside the declared audit root"));
}

#[test]
fn the_runtime_dependency_check_rejects_an_empty_client_registry() {
    let mut server = server();
    server.child.kill().expect("stop the serving process");
    server.child.wait().expect("reap the serving process");
    fs::remove_file(server.root.join("clients/scheduler.yaml"))
        .expect("remove scheduler registration");
    fs::remove_file(server.root.join("clients/reporter.yaml"))
        .expect("remove reporter registration");

    let output = Command::new(env!("CARGO_BIN_EXE_mint"))
        .arg("check")
        .arg("--config")
        .arg(&server.config)
        .arg("--require-runtime-dependencies")
        .output()
        .expect("the checker runs");

    assert!(
        !output.status.success(),
        "a Mint deployment with no registered clients must not pass runtime readiness"
    );
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

/// A refused request must not put the signed assertion back on the terminal.
///
/// `--url` and `--audience` are separate flags precisely so the assertion can be
/// audience-bound to the public endpoint while the request travels over
/// loopback. Point `--url` at the wrong host and the assertion, still valid at
/// the real Mint until it expires, is now that host's to echo. Repeating an
/// arbitrary body into stderr writes it to the operator's logs and scrollback
/// too, which is a second place to lose it from.
#[test]
fn a_refusal_does_not_echo_the_signed_assertion_back() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind an echoing endpoint");
    let port = listener.local_addr().expect("a bound address").port();
    let echo = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept the token request");
        let mut request = Vec::new();
        // The form is small and the client closes after it, so reading to the
        // content length is not worth a parser here.
        let mut buffer = [0u8; 8192];
        loop {
            let read = std::io::Read::read(&mut stream, &mut buffer).expect("read the request");
            request.extend_from_slice(&buffer[..read]);
            if read == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let body = String::from_utf8_lossy(&request).into_owned();
        let payload = json!({
            "error": "invalid_request",
            "error_description": "unrecognized request",
            "received": body,
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        std::io::Write::write_all(&mut stream, response.as_bytes()).expect("write the refusal");
        body
    });

    let server = server();
    let mut command = Command::new(env!("CARGO_BIN_EXE_mint"));
    command
        .arg("token")
        .arg("--url")
        .arg(format!("http://127.0.0.1:{port}/token"))
        .arg("--audience")
        .arg(server.assertion_audience())
        .arg("--client-id")
        .arg("scheduler")
        .arg("--key")
        .arg(server.caller_key("scheduler"));
    let output = command.output().expect("the mint binary runs");
    let received = echo.join().expect("the echoing endpoint finished");

    let assertion = received
        .split("client_assertion=")
        .nth(1)
        .expect("the endpoint received an assertion")
        .split('&')
        .next()
        .expect("the assertion is a form value")
        .to_owned();
    assert!(
        assertion.len() > 64,
        "the test needs a real assertion to look for: {assertion}"
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(&assertion),
        "the refusal echoed the signed assertion back"
    );
    // The status and the OAuth error stay, because that is what tells an
    // operator which endpoint refused and why.
    assert!(
        stderr.contains("400") && stderr.contains("invalid_request"),
        "the refusal should still name the status and the error: {stderr}"
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
