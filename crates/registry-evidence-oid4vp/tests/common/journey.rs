//! A complete wallet journey over real processes and real HTTP on loopback,
//! shared by the composed gate (`evidence_journey.rs`) and the device-run
//! harness (`device_run.rs`): the real `evidence-oid4vp` and `evidence`
//! binaries, a test authorization server, the portal calls, a simulated
//! wallet, and the relying party's verification with the Evidence client.
//!
//! The example deployment is the default. A `Setup` swaps the public origin,
//! the client identifier and the trusted issuer in a temporary copy, so the
//! committed example stays untouched.
#![allow(dead_code)]

use std::{
    fs,
    io::Read as _,
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use crate::common::{canonical_tempdir, keys, now, Keys, Options, AUDIENCE, HOST};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_evidence_client::{
    ChannelKind, ChannelPolicy, EvidenceClient, EvidenceClientConfig, EvidenceClientError,
    EvidenceDefinitionsDocument, EvidenceRequestSpec, EvidenceResponseFormat, JwksDocument,
    StaticToken, SubjectExpectations, SubjectRequest, VerifiedEvidence,
};
use registry_platform_crypto::{
    generate_private_jwk,
    jwe::{encrypt_compact_ecdh_es_for_tests, JweEnc},
    jws::{parse_compact_jws, JwsLimits},
    sign, GeneratedKeyAlgorithm, PrivateJwk, SigningAlgorithm,
};
use registry_platform_testing::{TestActorKind, TestAuthorizationServer, TestClient};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

/// The synthetic trusted issuer the example pins. TEST-ONLY key material: the
/// public key below belongs to no real issuer and protects nothing.
pub const ISSUER_TEST_PUBLIC: &str = "LC1rBDiHo7eDhVqNR9jB4WgF9TK2KJSeGnJhHhrC87g";
pub const ISSUER_KEY_ID: &str = "example-issuer-test-key";
pub const ISSUER: &str = "https://issuer.example.org";
pub const CREDENTIAL_TYPE: &str = "https://credentials.example.org/example-credential";

pub const EVIDENCE_RESOURCE: &str = "urn:example:resource:wallet-presentation-evidence";
pub const EVIDENCE_AUDIENCE: &str = "urn:example:audience:wallet-app";
pub const EVIDENCE_TAG: &str = "wallet-service";
pub const POSSESSION: &str = "urn:example:requirement:credential-possession:v1";
pub const IDENTITY: &str = "urn:example:requirement:identity-match:v1";

pub const APPLICANT: &str = "applicant-1";
pub const STARTUP_DEADLINE: Duration = Duration::from_secs(60);

/// The name of the example's disclosed claim.
const EXAMPLE_NAME_CLAIM: &str = "name";

pub fn example_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/examples/wallet-presentation")
}

pub fn read_example(name: &str) -> String {
    fs::read_to_string(example_dir().join(name))
        .unwrap_or_else(|error| panic!("the example file {name} is readable: {error}"))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn required_binary(name: &str) -> PathBuf {
    let path = std::env::var_os(name).unwrap_or_else(|| {
        panic!("{name} must name the built binary: build it and set {name}, this gate never skips")
    });
    let path = PathBuf::from(path);
    assert!(path.is_file(), "{name} names {path:?}, which is not a file");
    path
}

pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("a loopback port is free")
        .local_addr()
        .expect("the bound address")
        .port()
}

/// A service process killed when dropped. Its log is kept in the deployment
/// directory and printed when the test panics.
pub struct Service {
    name: &'static str,
    child: Child,
    log: PathBuf,
}

impl Service {
    pub fn spawn(name: &'static str, mut command: Command, log: PathBuf) -> Self {
        let file = fs::File::create(&log).expect("the service log is created");
        let child = command
            .stdout(Stdio::from(
                file.try_clone().expect("the log is duplicated"),
            ))
            .stderr(Stdio::from(file))
            .spawn()
            .unwrap_or_else(|error| panic!("{name} starts: {error}"));
        Self { name, child, log }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            eprintln!("{} could not be stopped: {error}", self.name);
        }
        if let Err(error) = self.child.wait() {
            eprintln!("{} could not be reaped: {error}", self.name);
        }
        if std::thread::panicking() {
            let mut text = String::new();
            if let Ok(mut file) = fs::File::open(&self.log) {
                if let Err(error) = file.read_to_string(&mut text) {
                    eprintln!("{} log unreadable: {error}", self.name);
                }
            }
            eprintln!("---- {} log ----\n{text}", self.name);
        }
    }
}

pub fn run(mut command: Command, what: &str) -> Output {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{what} starts: {error}"));
    assert!(
        output.status.success(),
        "{what} failed ({}):\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Copy a tree with its modes. A read-only directory takes its mode after its
/// contents are in place.
pub fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("the destination directory is created");
    for entry in fs::read_dir(from).expect("the source directory is read") {
        let entry = entry.expect("a directory entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("the entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("the file is copied");
        }
    }
    let mode = fs::metadata(from).expect("the source mode").permissions();
    fs::set_permissions(to, mode).expect("the destination mode is set");
}

pub fn write_private(path: &Path, contents: &[u8]) {
    fs::write(path, contents).expect("the private file is written");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("the private file mode is set");
}

pub fn replaced(text: &str, from: &str, to: &str) -> String {
    assert!(text.contains(from), "the example no longer contains {from}");
    text.replace(from, to)
}

pub async fn wait_healthy(http: &reqwest::Client, base: &str, service: &Service) {
    let started = Instant::now();
    loop {
        if let Ok(response) = http.get(format!("{base}/health")).send().await {
            if response.status().is_success() {
                return;
            }
        }
        assert!(
            started.elapsed() < STARTUP_DEADLINE,
            "{} did not become healthy at {base}",
            service.name
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ---------------------------------------------------------------------------
// What a run varies.
// ---------------------------------------------------------------------------

/// The trusted issuer of the presented credential and what is asked of it.
#[derive(Clone)]
pub struct Trust {
    /// The credential's `iss`.
    pub issuer: String,
    /// The credential's `vct`.
    pub vct: String,
    /// The issuer's public JWKs.
    pub keys: Vec<Value>,
    /// The top-level claim that holds the name.
    pub name_claim: String,
    /// The oldest credential, as seconds since its `iat`, the verifier and the
    /// relying party accept.
    pub maximum_credential_age_seconds: u64,
}

impl Trust {
    /// The synthetic issuer the committed example pins.
    pub fn example() -> Self {
        Self {
            issuer: ISSUER.to_owned(),
            vct: CREDENTIAL_TYPE.to_owned(),
            keys: vec![json!({
                "kty": "OKP", "crv": "Ed25519", "kid": ISSUER_KEY_ID, "x": ISSUER_TEST_PUBLIC,
            })],
            name_claim: EXAMPLE_NAME_CLAIM.to_owned(),
            maximum_credential_age_seconds: 3600,
        }
    }
}

/// How the verifier names and signs for itself toward the wallet.
#[derive(Clone)]
pub enum ClientKind {
    /// `x509_san_dns` with a generated self-signed leaf for the public host.
    GeneratedX509SanDns,
    /// `x509_san_dns` with a certificate chain and key the operator supplies
    /// (files holding the PEM chain and the private JWK).
    X509SanDns { chain: PathBuf, key: PathBuf },
    /// `decentralized_identifier` over `did:web:<host>` with a generated
    /// Ed25519 key the service publishes.
    DidWeb,
    /// `pre-registered` under `client_id` with a generated Ed25519 key the
    /// service publishes at `/v1/jwks`.
    PreRegistered { client_id: String },
}

/// What a deployment varies from the committed example. The default is the
/// example, unchanged but for loopback ports and generated keys.
#[derive(Clone)]
pub struct Setup {
    /// The public HTTPS origin the wallet reaches. The default keeps the
    /// example's placeholder host, which only a simulated wallet that reads the
    /// loopback listener can use.
    pub public_url: Option<String>,
    /// The loopback port the verifier listens on, so a tunnel can forward to
    /// it. A free port when absent.
    pub listen_port: Option<u16>,
    pub client: ClientKind,
    /// A trusted issuer other than the example's.
    pub trust: Option<Trust>,
    /// The session lifetime; the example's when absent.
    pub session_ttl_seconds: Option<u64>,
}

impl Setup {
    pub fn example() -> Self {
        Self {
            public_url: None,
            listen_port: None,
            client: ClientKind::GeneratedX509SanDns,
            trust: None,
            session_ttl_seconds: None,
        }
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

/// Rewrite the pack's protocol configurations and the name script for `trust`
/// and `client_id`, and the digests the pack pins for them. The name claim must
/// be a plain claim name (letters, digits, `_`, `-`).
fn retarget_pack(project: &Path, trust: &Trust, client_id: &str) {
    let pack_dir = project.join("adapter-packs/wallet-session");
    let pack_path = pack_dir.join("pack.yaml");
    let mut pack: Value = serde_json::from_slice(&fs::read(&pack_path).expect("the pack is read"))
        .expect("the pack is JSON");
    for endpoint in pack["endpoints"]
        .as_array_mut()
        .expect("the pack lists endpoints")
    {
        let config = &mut endpoint["hostProtocol"]["config"];
        let path = pack_dir.join(config["path"].as_str().expect("a protocol path"));
        let mut protocol: Value = serde_json::from_slice(&fs::read(&path).expect("read"))
            .expect("the protocol configuration is JSON");
        protocol["clientId"] = json!(client_id);
        protocol["trust"][0]["issuer"] = json!(trust.issuer);
        protocol["trust"][0]["vct"] = json!([trust.vct]);
        protocol["trust"][0]["keys"]["jwks"] = json!(trust.keys);
        protocol["policy"]["vct"] = json!([trust.vct]);
        protocol["maximumCredentialAgeSeconds"] = json!(trust.maximum_credential_age_seconds);
        if protocol["disclosedClaims"]
            .as_array()
            .is_some_and(|claims| !claims.is_empty())
        {
            protocol["disclosedClaims"] = json!([trust.name_claim]);
        }
        let bytes = serde_json::to_vec_pretty(&protocol).expect("the protocol encodes");
        fs::write(&path, &bytes).expect("the protocol configuration is written");
        config["digest"] = json!(sha256_digest(&bytes));
    }
    // The identity route reads the disclosed name by its claim name.
    let script_path = pack_dir.join("scripts/wallet.rhai");
    let script = replaced(
        &fs::read_to_string(&script_path).expect("the script is read"),
        "exchange.body.values.name",
        &format!("exchange.body.values[\"{}\"]", trust.name_claim),
    );
    fs::write(&script_path, &script).expect("the script is written");
    for entry in pack["scripts"]
        .as_array_mut()
        .expect("the pack lists scripts")
    {
        assert_eq!(entry["path"], "scripts/wallet.rhai");
        entry["digest"] = json!(sha256_digest(script.as_bytes()));
    }
    fs::write(
        &pack_path,
        serde_json::to_vec_pretty(&pack).expect("the pack encodes"),
    )
    .expect("the pack is written");
}

// ---------------------------------------------------------------------------
// The deployment under test.
// ---------------------------------------------------------------------------

/// A temporary directory whose read-only bundle is made removable before it
/// is deleted.
pub struct Directory(tempfile::TempDir);

impl Directory {
    pub fn path(&self) -> &Path {
        self.0.path()
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        make_removable(self.0.path());
    }
}

fn make_removable(path: &Path) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("{} could not be inspected: {error}", path.display());
            return;
        }
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    let mode = if metadata.is_dir() { 0o700 } else { 0o600 };
    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(mode)) {
        eprintln!("{} could not be made removable: {error}", path.display());
    }
    if metadata.is_dir() {
        match fs::read_dir(path) {
            Ok(entries) => entries
                .flatten()
                .for_each(|entry| make_removable(&entry.path())),
            Err(error) => eprintln!("{} could not be listed: {error}", path.display()),
        }
    }
}

/// Fields drop in order: the services stop and print their logs before the
/// directory holding the logs is removed.
pub struct Deployment {
    _verifier: Service,
    _evidence: Service,
    _directory: Directory,
    pub idp: TestAuthorizationServer,
    /// The verifier's loopback origin, for the portal and Evidence roles.
    pub verifier: String,
    /// The public origin written into request URIs.
    pub public_url: String,
    /// The client identifier the verifier presents to the wallet.
    pub client_id: String,
    pub trust: Trust,
    pub http: reqwest::Client,
    pub client_kind: ClientKind,
    pub client: EvidenceClient,
    pub leaf: Keys,
}

impl Deployment {
    pub async fn start(setup: Setup) -> Self {
        let evidence_bin = required_binary("EVIDENCE_BIN");
        let evidencectl_bin = required_binary("EVIDENCECTL_BIN");

        let idp = TestAuthorizationServer::builder()
            .client(TestClient::new("portal").with_resource(AUDIENCE))
            .client(TestClient::new("evidence").with_resource(AUDIENCE))
            .client(
                TestClient::new("relying")
                    .with_resource(EVIDENCE_RESOURCE)
                    .with_actor_kind(TestActorKind::Service),
            )
            .start()
            .await;
        let directory = Directory(canonical_tempdir());
        let verifier_port = setup.listen_port.unwrap_or_else(free_port);
        let evidence_port = free_port();
        let verifier = format!("http://127.0.0.1:{verifier_port}");
        let evidence = format!("http://127.0.0.1:{evidence_port}");
        let http = reqwest::Client::new();
        let public_url = setup
            .public_url
            .clone()
            .unwrap_or_else(|| format!("https://{HOST}"));
        let public_url = public_url.trim_end_matches('/').to_owned();
        let public_host = url::Url::parse(&public_url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_owned))
            .unwrap_or_else(|| panic!("the public URL {public_url} has no host"));
        let trust = setup.trust.clone().unwrap_or_else(Trust::example);
        let client_id = match &setup.client {
            ClientKind::GeneratedX509SanDns | ClientKind::X509SanDns { .. } => {
                format!("x509_san_dns:{public_host}")
            }
            ClientKind::DidWeb => format!("decentralized_identifier:did:web:{public_host}"),
            ClientKind::PreRegistered { client_id } => client_id.clone(),
        };

        // The verifier: secrets, runtime file, process.
        let verifier_secrets = directory.path().join("verifier-secrets");
        fs::create_dir(&verifier_secrets).expect("the secret directory is created");
        fs::set_permissions(&verifier_secrets, fs::Permissions::from_mode(0o700))
            .expect("the secret directory mode is set");
        let leaf = keys(&Options::default());
        let (chain, signing) = match &setup.client {
            ClientKind::X509SanDns { chain, key } => (
                fs::read(chain).unwrap_or_else(|error| panic!("the chain file is read: {error}")),
                fs::read(key).unwrap_or_else(|error| panic!("the key file is read: {error}")),
            ),
            _ => (
                leaf.chain_pem.clone().into_bytes(),
                leaf.private_jwk.clone().into_bytes(),
            ),
        };
        write_private(&verifier_secrets.join("chain.pem"), &chain);
        write_private(&verifier_secrets.join("signing.jwk.json"), &signing);
        write_private(
            &verifier_secrets.join("did-signing.jwk.json"),
            leaf.did_jwk.as_bytes(),
        );
        write_private(
            &verifier_secrets.join("registered-signing.jwk.json"),
            leaf.registered_jwk.as_bytes(),
        );
        write_private(&verifier_secrets.join("audit-hash-key"), &[7u8; 48]);
        let runtime = read_example("oid4vp-runtime.yaml");
        let runtime = replaced(&runtime, "http://127.0.0.1:8082", &idp.issuer());
        let runtime = replaced(
            &runtime,
            "bind: 127.0.0.1:8095",
            &format!("bind: 127.0.0.1:{verifier_port}"),
        );
        let runtime = replaced(
            &runtime,
            "/run/secrets/wallet-verifier",
            &verifier_secrets.display().to_string(),
        );
        let runtime = replaced(
            &runtime,
            "/var/lib/wallet-verifier/audit.jsonl",
            &directory
                .path()
                .join("verifier-audit.jsonl")
                .display()
                .to_string(),
        );
        let runtime = replaced(
            &runtime,
            "publicBaseUrl: https://verifier.example.org",
            &format!("publicBaseUrl: {public_url}"),
        );
        let runtime = match &setup.client {
            ClientKind::GeneratedX509SanDns | ClientKind::X509SanDns { .. } => runtime,
            ClientKind::DidWeb => replaced(
                &runtime,
                "    type: x509-san-dns\n    certificateChainRef: secret:file/chain.pem\n    signingKeyRef: secret:file/signing.jwk.json\n",
                &format!(
                    "    type: decentralized-identifier\n    did: did:web:{public_host}\n    signingKeyRef: secret:file/did-signing.jwk.json\n"
                ),
            ),
            ClientKind::PreRegistered { client_id } => replaced(
                &runtime,
                "    type: x509-san-dns\n    certificateChainRef: secret:file/chain.pem\n    signingKeyRef: secret:file/signing.jwk.json\n",
                &format!(
                    "    type: pre-registered\n    clientId: {client_id}\n    signingKeyRef: secret:file/registered-signing.jwk.json\n"
                ),
            ),
        };
        let runtime = if setup.trust.is_some() {
            let runtime = runtime.replace(CREDENTIAL_TYPE, &trust.vct);
            replaced(
                &runtime,
                "- path: [name]",
                &format!("- path: [{}]", trust.name_claim),
            )
        } else {
            runtime
        };
        let runtime = match setup.session_ttl_seconds {
            Some(seconds) => replaced(
                &runtime,
                "sessionTtlSeconds: 300",
                &format!("sessionTtlSeconds: {seconds}"),
            ),
            None => runtime,
        };
        let runtime_path = directory.path().join("oid4vp-runtime.yaml");
        write_private(&runtime_path, runtime.as_bytes());
        let mut command = Command::new(env!("CARGO_BIN_EXE_evidence-oid4vp"));
        command
            .args(["serve", "--runtime-config"])
            .arg(&runtime_path)
            .env_remove("EVIDENCE_OID4VP_CONFIG");
        let verifier_service = Service::spawn(
            "evidence-oid4vp",
            command,
            directory.path().join("verifier.log"),
        );

        // Evidence: the example project in a temporary copy with this run's
        // ports and issuer, generated keys, a packaged bundle and an
        // activated authority.
        let project = directory.path().join("project");
        copy_tree(&example_dir(), &project);
        if setup.trust.is_some() {
            retarget_pack(&project, &trust, &client_id);
        }
        let target_path = project.join("wallet-target.yaml");
        let target = fs::read_to_string(&target_path).expect("the target is readable");
        let target = replaced(&target, "http://127.0.0.1:8082", &idp.issuer());
        let target = replaced(&target, "http://127.0.0.1:8080", &evidence);
        let target = replaced(
            &target,
            "bind: 127.0.0.1:8080",
            &format!("bind: 127.0.0.1:{evidence_port}"),
        );
        let target = replaced(&target, "http://127.0.0.1:8095", &verifier);
        fs::write(&target_path, target).expect("the target is written");

        let secrets = project.join(".generated/secrets");
        fs::create_dir_all(&secrets).expect("the secret directory is created");
        fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))
            .expect("the secret directory mode is set");
        let ctl = |args: &[&str], what: &str| {
            let mut command = Command::new(&evidencectl_bin);
            command
                .args(args)
                .env("EVIDENCE_BIN", &evidence_bin)
                .current_dir(&project);
            run(command, what)
        };
        ctl(
            &["keygen", "signing", "--output-dir", ".generated/secrets"],
            "evidencectl keygen signing",
        );
        for name in ["audit-hmac-key", "subject-binding-hmac-key"] {
            ctl(
                &[
                    "keygen",
                    "secret",
                    "--output",
                    &format!(".generated/secrets/{name}"),
                ],
                "evidencectl keygen secret",
            );
        }
        let read_token = idp.issue_access_token(
            "evidence",
            "evidence-service",
            AUDIENCE,
            "oid4vp:read-result",
            i64::try_from(now() + 240).expect("the expiry fits"),
        );
        write_private(&secrets.join("verifier-read-token"), read_token.as_bytes());

        let candidate = directory.path().join("candidate");
        ctl(
            &[
                "package",
                ".",
                "--target",
                "wallet-target.yaml",
                "--output",
                &candidate.display().to_string(),
            ],
            "evidencectl package",
        );
        // The runtime serves only a read-only bundle; the copy keeps the
        // packaged modes.
        copy_tree(
            &candidate.join("bundle"),
            &project.join(".generated/package"),
        );
        let runtime_path = candidate.join("runtime.yaml");
        let mut command = Command::new(&evidence_bin);
        command
            .args(["authority", "activate", "--runtime-config"])
            .arg(&runtime_path)
            .arg("--document")
            .arg(candidate.join("compiled-authority.yaml"));
        run(command, "evidence authority activate");
        let mut command = Command::new(&evidence_bin);
        command
            .args(["serve", "--runtime-config"])
            .arg(&runtime_path);
        let evidence_service =
            Service::spawn("evidence", command, directory.path().join("evidence.log"));
        wait_healthy(&http, &verifier, &verifier_service).await;
        wait_healthy(&http, &evidence, &evidence_service).await;

        // The relying party pins the signing key the project generated.
        let public = fs::read(secrets.join("signing-p256-public.jwk.json"))
            .expect("the public signing key is readable");
        let jwks: JwksDocument = serde_json::from_value(
            json!({"keys": [serde_json::from_slice::<Value>(&public).expect("the key is JSON")]}),
        )
        .expect("the key set parses");
        let relying_token = idp.issue_access_token_with_claims(
            "relying",
            "relying-app",
            EVIDENCE_RESOURCE,
            "evidence:request",
            i64::try_from(now() + 900).expect("the expiry fits"),
            [
                ("evidence_tags".to_owned(), json!([EVIDENCE_TAG])),
                ("evidence_audience".to_owned(), json!(EVIDENCE_AUDIENCE)),
            ]
            .into_iter()
            .collect(),
        );
        let client = EvidenceClient::new(EvidenceClientConfig::new(
            evidence.parse().expect("the Evidence origin parses"),
            Arc::new(StaticToken::new(&relying_token).expect("the credential is header-safe")),
            jwks,
            Vec::new(),
        ))
        .expect("the client configuration is usable");

        Self {
            _verifier: verifier_service,
            _evidence: evidence_service,
            _directory: directory,
            idp,
            verifier,
            public_url,
            client_id,
            trust,
            client_kind: setup.client,
            http,
            client,
            leaf,
        }
    }

    pub fn applicant_token(&self, subject: &str) -> String {
        self.idp.issue_access_token(
            "portal",
            subject,
            AUDIENCE,
            "oid4vp:session",
            i64::try_from(now() + 600).expect("the expiry fits"),
        )
    }

    // -- The portal role --------------------------------------------------

    pub async fn create_session(&self, applicant: &str, policy: &str) -> Session {
        let response = self
            .http
            .post(format!("{}/v1/sessions", self.verifier))
            .bearer_auth(self.applicant_token(applicant))
            .json(&json!({"policy": policy}))
            .send()
            .await
            .expect("the session request completes");
        assert_eq!(response.status(), 201, "{:?}", response.text().await);
        let body: Value = response.json().await.expect("the session is JSON");
        let request_uri = body["requestUri"].as_str().expect("a request URI");
        assert!(
            request_uri.starts_with(&format!("{}/v1/requests/", self.public_url)),
            "{request_uri}"
        );
        Session {
            applicant: applicant.to_owned(),
            reference: body["reference"].as_str().expect("a reference").to_owned(),
            request_id: request_uri
                .rsplit('/')
                .next()
                .expect("a request id")
                .to_owned(),
            request_uri: request_uri.to_owned(),
            wallet_invocation: body["walletInvocation"]
                .as_str()
                .expect("a wallet invocation")
                .to_owned(),
        }
    }

    pub async fn status(&self, session: &Session) -> String {
        let response = self
            .http
            .get(format!(
                "{}/v1/sessions/{}",
                self.verifier, session.reference
            ))
            .bearer_auth(self.applicant_token(&session.applicant))
            .send()
            .await
            .expect("the status request completes");
        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.expect("the status is JSON");
        body["status"].as_str().expect("a status").to_owned()
    }

    /// Poll until the session reads as `received` or `failed`, or `bound`
    /// passes. Returns the last status read.
    pub async fn wait_for_presentation(&self, session: &Session, bound: Duration) -> String {
        let started = Instant::now();
        loop {
            let status = self.status(session).await;
            if status != "pending" || started.elapsed() >= bound {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn wait_until_received(&self, session: &Session) {
        let status = self.wait_for_presentation(session, STARTUP_DEADLINE).await;
        assert_eq!(status, "received", "the session never read as received");
    }

    // -- The simulated wallet ----------------------------------------------

    /// Fetch the request object, check it, and post an encrypted presentation
    /// of a credential signed by `issuer` carrying `claims`.
    pub async fn present(&self, session: &Session, issuer: &PrivateJwk, claims: &[(&str, &str)]) {
        let response = self
            .http
            .get(format!(
                "{}/v1/requests/{}",
                self.verifier, session.request_id
            ))
            .send()
            .await
            .expect("the request object is fetched");
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()["content-type"],
            "application/oauth-authz-req+jwt"
        );
        let jws = response.text().await.expect("the request object is text");
        let parsed = parse_compact_jws(&jws, &JwsLimits::default()).expect("a compact JWS");
        let key = match &self.client_kind {
            ClientKind::GeneratedX509SanDns => {
                let x5c = parsed.header()["x5c"][0]
                    .as_str()
                    .expect("the leaf certificate is in x5c");
                assert_eq!(
                    base64::engine::general_purpose::STANDARD
                        .decode(x5c)
                        .expect("x5c is base64"),
                    self.leaf.leaf_der
                );
                Some((&self.leaf.public_jwk, SigningAlgorithm::Es256))
            }
            ClientKind::DidWeb => Some((&self.leaf.did_public, SigningAlgorithm::EdDsa)),
            ClientKind::PreRegistered { .. } => {
                Some((&self.leaf.registered_public, SigningAlgorithm::EdDsa))
            }
            // The operator's own certificate is checked by the real wallet.
            ClientKind::X509SanDns { .. } => None,
        };
        let payload = match key {
            Some((public, algorithm)) => parsed
                .verify(public, &[algorithm])
                .expect("the request object is signed by the client identifier key")
                .to_vec(),
            None => URL_SAFE_NO_PAD
                .decode(jws.split('.').nth(1).expect("a JWS payload segment"))
                .expect("the payload is base64url"),
        };
        let payload = payload.as_slice();
        let request: Value = serde_json::from_slice(payload).expect("the request is JSON");
        let client_id = request["client_id"].as_str().expect("a client id");
        assert_eq!(client_id, self.client_id);

        // A query that asks for no claim carries no `claims` member.
        assert_eq!(
            request["dcql_query"]["credentials"][0]
                .get("claims")
                .is_none(),
            claims.is_empty(),
            "{request}"
        );
        let credential = sd_jwt_vc(
            issuer,
            &self.trust,
            claims,
            client_id,
            request["nonce"].as_str().expect("a nonce"),
        );
        let query_id = request["dcql_query"]["credentials"][0]["id"]
            .as_str()
            .expect("a credential query id");
        let key = request["client_metadata"]["jwks"]["keys"][0]
            .as_object()
            .expect("the response encryption key");
        let kid = key["kid"].as_str().expect("the response key id");
        let plaintext = json!({
            "vp_token": {query_id: [credential]},
            "state": request["state"],
        });
        let jwe = encrypt_compact_ecdh_es_for_tests(
            plaintext.to_string().as_bytes(),
            key,
            JweEnc::A128Gcm,
            b"",
            b"",
            Some(kid),
        )
        .expect("the wallet encrypts");
        let posted = self
            .http
            .post(format!(
                "{}/v1/responses/{}",
                self.verifier, session.request_id
            ))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(format!("response={jwe}"))
            .send()
            .await
            .expect("the response is posted");
        assert_eq!(posted.status(), 200, "{:?}", posted.text().await);
    }

    /// The read response the verifier gives Evidence for `session`. A read of a
    /// result consumes it.
    pub async fn read_presentation(&self, session: &Session) -> Value {
        let response = self.read_response(session).await;
        assert_eq!(response.status(), 200, "{:?}", response.text().await);
        response.json().await.expect("the read response is JSON")
    }

    /// The status of a read of `session`'s result.
    pub async fn read_status(&self, session: &Session) -> u16 {
        self.read_response(session).await.status().as_u16()
    }

    async fn read_response(&self, session: &Session) -> reqwest::Response {
        let token = self.idp.issue_access_token(
            "evidence",
            "evidence-service",
            AUDIENCE,
            "oid4vp:read-result",
            i64::try_from(now() + 240).expect("the expiry fits"),
        );
        self.http
            .post(format!("{}/v1/presentations/read", self.verifier))
            .bearer_auth(token)
            .json(&json!({
                "reference": session.reference,
                "principal": {"issuer": self.idp.issuer(), "subject": session.applicant},
            }))
            .send()
            .await
            .expect("the read request completes")
    }

    // -- Evidence ----------------------------------------------------------

    pub async fn definitions(&self) -> EvidenceDefinitionsDocument {
        self.client.discover().await.expect("discovery succeeds")
    }

    /// Request `requirement` for the session and principal, verifying under a
    /// policy that accepts the holder-presented channel.
    pub async fn request(
        &self,
        requirement: &str,
        session: &Session,
        principal_subject: &str,
        expected_name: Option<&str>,
    ) -> Result<VerifiedEvidence, EvidenceClientError> {
        let definitions = self.definitions().await;
        let mut values = vec![
            ("session-reference", session.reference.clone()),
            ("principal-issuer", self.idp.issuer()),
            ("principal-subject", principal_subject.to_owned()),
        ];
        if let Some(name) = expected_name {
            values.push(("expected-name", name.to_owned()));
        }
        let prepared = self
            .client
            .prepare(spec(&definitions, requirement, &values))
            .expect("the specification is accepted")
            .with_channel_policy(ChannelPolicy {
                accepted_channels: vec![ChannelKind::HolderPresented],
                maximum_credential_age_seconds: Some(self.trust.maximum_credential_age_seconds),
            })
            .expect("the channel policy is in bounds");
        self.client.request_and_verify(&prepared).await
    }
}

pub struct Session {
    pub applicant: String,
    pub reference: String,
    pub request_id: String,
    /// The public URL a wallet fetches the request object from.
    pub request_uri: String,
    /// `openid4vp://authorize?client_id=...&request_uri=...`.
    pub wallet_invocation: String,
}

/// A request specification built from the deployment's published definition.
pub fn spec(
    definitions: &EvidenceDefinitionsDocument,
    requirement: &str,
    values: &[(&str, String)],
) -> EvidenceRequestSpec {
    let definition = definitions
        .definition(requirement)
        .expect("the requester is entitled to the requirement");
    EvidenceRequestSpec {
        response_format: EvidenceResponseFormat::SignedJws,
        requirement: definition.requirement.clone(),
        purpose: definition.purpose.clone(),
        audience: EVIDENCE_AUDIENCE.to_owned(),
        evidence_type: definition.evidence_type.clone(),
        issued_by: definitions.issued_by.clone(),
        provided_by: definitions.provided_by.clone(),
        configuration_revision: definition.configuration_revision.clone(),
        expected_assurance_profile: definitions.assurance_profile,
        subjects: definition
            .subjects
            .iter()
            .map(|subject| SubjectRequest {
                role: subject.role.clone(),
                selector_profile: subject.selector.profile.clone(),
                selector_values: Some(
                    subject
                        .selector
                        .fields
                        .iter()
                        .map(|field| {
                            let value = values
                                .iter()
                                .find(|(name, _)| *name == field.name())
                                .unwrap_or_else(|| panic!("no value for {}", field.name()));
                            (field.name().to_owned(), value.1.clone().into())
                        })
                        .collect(),
                ),
            })
            .collect(),
        holder_keys: Vec::new(),
        expected_outputs: definition
            .concepts
            .iter()
            .map(|concept| {
                concept
                    .scalar_expected_output()
                    .expect("the definition publishes scalar concepts")
            })
            .collect(),
        maximum_assertion_lifetime_seconds: 600,
        clock_skew_seconds: 30,
        subject_expectations: SubjectExpectations::AcceptFirstUse,
    }
}

// ---------------------------------------------------------------------------
// The credential the simulated wallet presents.
// ---------------------------------------------------------------------------

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn compact(header: &Value, payload: &Value, key: &PrivateJwk) -> String {
    let input = format!(
        "{}.{}",
        b64(&serde_json::to_vec(header).expect("the header encodes")),
        b64(&serde_json::to_vec(payload).expect("the payload encodes"))
    );
    let signature = sign(input.as_bytes(), key).expect("the token is signed");
    format!("{input}.{}", b64(&signature))
}

/// An SD-JWT VC of `trust`'s issuer and type with one selectively disclosable
/// claim per entry of `claims` and a key binding JWT over `client_id` and
/// `nonce`, held by a fresh key.
pub fn sd_jwt_vc(
    issuer: &PrivateJwk,
    trust: &Trust,
    claims: &[(&str, &str)],
    client_id: &str,
    nonce: &str,
) -> String {
    let holder = generate_private_jwk(GeneratedKeyAlgorithm::Es256).expect("a holder key");
    let mut holder_public = serde_json::to_value(holder.public()).expect("the key encodes");
    let public = holder_public.as_object_mut().expect("a JWK object");
    public.remove("kid");
    public.remove("alg");
    let issued_at = now();
    let mut digests = Vec::new();
    let mut disclosures = Vec::new();
    for (name, value) in claims {
        let disclosure = b64(
            &serde_json::to_vec(&json!([format!("salt-{name}"), name, value]))
                .expect("the disclosure encodes"),
        );
        digests.push(b64(&Sha256::digest(disclosure.as_bytes())));
        disclosures.push(disclosure);
    }
    let payload = json!({
        "iss": trust.issuer,
        "vct": trust.vct,
        "iat": issued_at - 100,
        "exp": issued_at + 3600,
        "cnf": {"jwk": holder_public},
        "_sd": digests,
        "_sd_alg": "sha-256",
    });
    let header = json!({"alg": "EdDSA", "typ": "dc+sd-jwt", "kid": issuer.kid});
    let mut out = compact(&header, &payload, issuer);
    out.push('~');
    for disclosure in &disclosures {
        out.push_str(disclosure);
        out.push('~');
    }
    let binding = json!({
        "iat": issued_at,
        "aud": client_id,
        "nonce": nonce,
        "sd_hash": b64(&Sha256::digest(out.as_bytes())),
    });
    out.push_str(&compact(
        &json!({"alg": "ES256", "typ": "kb+jwt"}),
        &binding,
        &holder,
    ));
    out
}

/// The one boolean output of a verified assertion, or `None` when the
/// assertion carries anything else.
pub fn boolean_output(verified: &VerifiedEvidence) -> Option<bool> {
    let values = serde_json::to_value(verified.evidence().supported_values.clone()).ok()?;
    let values = values.as_array()?;
    match values.as_slice() {
        [only] => only["value"].as_bool(),
        _ => None,
    }
}
