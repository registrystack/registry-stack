//! A complete deployment on loopback: a test authorization server, generated
//! certificates, secrets in a temporary directory, and the service router.
#![allow(dead_code)]

use std::{
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use axum_test::TestServer;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use rcgen::{CertificateParams, KeyPair};
use registry_evidence_oid4vp::{
    config::Oid4vpConfig,
    service::{build_app, StartupError, VerifierService},
    session::Clock,
};
use registry_platform_crypto::{
    generate_private_jwk, GeneratedKeyAlgorithm, PrivateJwk, PublicJwk,
};
use registry_platform_testing::{TestAuthorizationServer, TestClient};

pub const HOST: &str = "verifier.example.org";
pub const AUDIENCE: &str = "https://verifier.example.org";
pub const SESSION_SCOPE: &str = "oid4vp:session";
pub const READ_SCOPE: &str = "oid4vp:read-result";
/// The `clientId` of the pre-registered identifier the harness declares.
pub const REGISTERED_CLIENT_ID: &str = "evidence-verifier";

pub fn canonical_tempdir() -> tempfile::TempDir {
    // The reader refuses a path through a symbolic link, and the system
    // temporary directory is one on some hosts.
    let base = std::env::temp_dir()
        .canonicalize()
        .expect("the temporary directory resolves");
    tempfile::tempdir_in(base).expect("a temporary directory")
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// What a test varies about the deployment.
#[derive(Clone)]
pub struct Options {
    /// `x509-san-dns` or `x509-hash`.
    pub client_identifier: &'static str,
    /// DNS names in the leaf certificate.
    pub sans: Vec<String>,
    /// Validity of the leaf, as years.
    pub not_before_year: i32,
    pub not_after_year: i32,
    /// Sign with a key other than the leaf's.
    pub mismatched_key: bool,
    pub trusted_authorities: bool,
    /// Declare the Inji identifiers (`decentralized-identifier` and
    /// `pre-registered`) and a policy for each.
    pub inji: bool,
    pub maximum_live_sessions: u32,
    pub maximum_held_presentation_bytes: u64,
    pub session_creation_burst: u32,
    pub wallet_request_burst: u32,
    pub wallet_response_burst: u32,
    pub response_burst_per_request: u32,
    pub evidence_read_burst: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            client_identifier: "x509-san-dns",
            sans: vec![HOST.to_owned()],
            not_before_year: 2020,
            not_after_year: 2090,
            mismatched_key: false,
            trusted_authorities: false,
            inji: true,
            maximum_live_sessions: 64,
            maximum_held_presentation_bytes: 268_435_456,
            session_creation_burst: 20,
            wallet_request_burst: 50,
            wallet_response_burst: 50,
            response_burst_per_request: 20,
            evidence_read_burst: 50,
        }
    }
}

pub struct Keys {
    pub chain_pem: String,
    pub private_jwk: String,
    pub public_jwk: PublicJwk,
    pub leaf_der: Vec<u8>,
    /// The Ed25519 key of the `decentralized-identifier` identifier.
    pub did_jwk: String,
    pub did_public: PublicJwk,
    /// The Ed25519 key of the `pre-registered` identifier.
    pub registered_jwk: String,
    pub registered_public: PublicJwk,
}

/// A fresh Ed25519 private JWK as the text a secret file holds, and its public
/// half. The JWK carries no `kid`; the service names its own.
pub fn ed25519_pair() -> (String, PublicJwk) {
    let private = generate_private_jwk(GeneratedKeyAlgorithm::Ed25519).expect("an Ed25519 key");
    (private_json(&private), private.public())
}

/// The text of `private`, whose `Serialize` writes only the public half.
pub fn private_json(private: &PrivateJwk) -> String {
    serde_json::json!({
        "kty": private.kty,
        "crv": private.crv,
        "alg": private.alg,
        "x": private.x,
        "d": private.d,
    })
    .to_string()
}

/// A P-256 leaf certificate and the private JWK of its key.
pub fn keys(options: &Options) -> Keys {
    let key = KeyPair::generate().expect("a P-256 key");
    let leaf = leaf_for(&key, options);
    let signing = if options.mismatched_key {
        KeyPair::generate().expect("another key")
    } else {
        key
    };
    let jwk = private_jwk(&signing);
    let public: PublicJwk = serde_json::from_value(public_of(&jwk)).expect("a public JWK");
    let (did_jwk, did_public) = ed25519_pair();
    let (registered_jwk, registered_public) = ed25519_pair();
    Keys {
        did_jwk,
        did_public,
        registered_jwk,
        registered_public,
        chain_pem: pem(leaf.der()),
        private_jwk: jwk.to_string(),
        public_jwk: public,
        leaf_der: leaf.der().to_vec(),
    }
}

fn pem(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

fn leaf_for(key: &KeyPair, options: &Options) -> rcgen::Certificate {
    let mut params = CertificateParams::new(options.sans.clone()).expect("certificate parameters");
    params.not_before = rcgen::date_time_ymd(options.not_before_year, 1, 1);
    params.not_after = rcgen::date_time_ymd(options.not_after_year, 1, 1);
    params.self_signed(key).expect("a self-signed certificate")
}

fn public_of(private: &serde_json::Value) -> serde_json::Value {
    let mut public = private.clone();
    public.as_object_mut().unwrap().remove("d");
    public
}

/// The private JWK of an rcgen P-256 key. The PKCS#8 document ring writes
/// carries the 32-byte scalar after a fixed 36-byte prefix.
fn private_jwk(key: &KeyPair) -> serde_json::Value {
    let der = key.serialize_der();
    let scalar = &der[36..68];
    let point = key.public_key_raw();
    assert_eq!(point.len(), 65);
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": "verifier-request-key",
        "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        "d": URL_SAFE_NO_PAD.encode(scalar),
    })
}

pub struct Harness {
    pub idp: TestAuthorizationServer,
    pub dir: tempfile::TempDir,
    pub keys: Keys,
    pub time: Arc<AtomicU64>,
    pub config_path: PathBuf,
    pub audit_path: PathBuf,
}

fn write_secret(dir: &std::path::Path, name: &str, contents: &[u8]) {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

impl Harness {
    pub async fn new(options: &Options) -> Self {
        let idp = TestAuthorizationServer::builder()
            .client(TestClient::new("portal").with_resource(AUDIENCE))
            .client(TestClient::new("portal-b").with_resource(AUDIENCE))
            .client(TestClient::new("evidence").with_resource(AUDIENCE))
            .start()
            .await;
        let dir = canonical_tempdir();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir(&secrets).unwrap();
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
        let keys = keys(options);
        write_secret(&secrets, "chain.pem", keys.chain_pem.as_bytes());
        write_secret(&secrets, "signing.jwk.json", keys.private_jwk.as_bytes());
        write_secret(&secrets, "did-signing.jwk.json", keys.did_jwk.as_bytes());
        write_secret(
            &secrets,
            "registered-signing.jwk.json",
            keys.registered_jwk.as_bytes(),
        );
        write_secret(&secrets, "audit-hash-key", &[7u8; 48]);
        let audit_path = dir.path().join("audit.jsonl");

        let authorities = if options.trusted_authorities {
            "    trustedAuthorities:\n      - type: aki\n        values: [c2lnbmluZy1rZXktaWRlbnRpZmllcg]\n"
        } else {
            ""
        };
        let (inji_identifiers, inji_policies) = if options.inji {
            (
                format!(
                    r"  - id: inji-did
    type: decentralized-identifier
    did: did:web:{HOST}
    signingKeyRef: secret:file/did-signing.jwk.json
  - id: inji-registered
    type: pre-registered
    clientId: {REGISTERED_CLIENT_ID}
    signingKeyRef: secret:file/registered-signing.jwk.json
"
                ),
                r"  - id: inji-did-id
    clientIdentifier: inji-did
    credentials:
      - id: pid
        format: dc+sd-jwt
        vctValues: [https://credentials.example.org/national-id]
        claims:
          - path: [given_name]
    acceptedResponseEncryption: [A256GCM]
  - id: inji-registered-id
    clientIdentifier: inji-registered
    credentials:
      - id: pid
        format: dc+sd-jwt
        vctValues: [https://credentials.example.org/national-id]
        claims:
          - path: [given_name]
    acceptedResponseEncryption: [A256GCM]
",
            )
        } else {
            (String::new(), "")
        };
        let yaml = format!(
            r"apiVersion: id.registrystack.org/formats/evidence/oid4vp-runtime/v1alpha1
kind: EvidenceOid4vpRuntimeConfig
publicBaseUrl: https://{HOST}
listener:
  bind: 127.0.0.1:8095
secretProviders:
  file:
    root: {secrets}
audit:
  destination: file
  path: {audit}
  hashKeyRef: secret:file/audit-hash-key
applicantTokens:
  issuer: {issuer}
  audience: {AUDIENCE}
  allowInsecureHttp: true
  jwksSource:
    type: uri
    uri: {jwks}
  algorithms: [EdDSA]
  requiredScope: {SESSION_SCOPE}
evidenceCredentials:
  issuer: {issuer}
  audience: {AUDIENCE}
  allowInsecureHttp: true
  jwksSource:
    type: uri
    uri: {jwks}
  algorithms: [EdDSA]
  allowedClient: evidence
  requiredScope: oid4vp:read-result
clientIdentifiers:
  - id: haip
    type: {kind}
    certificateChainRef: secret:file/chain.pem
    signingKeyRef: secret:file/signing.jwk.json
{inji_identifiers}policies:
  - id: national-id
    clientIdentifier: haip
    credentials:
      - id: national_id
        format: dc+sd-jwt
        vctValues: [https://credentials.example.org/national-id]
        claims:
          - path: [given_name]
          - path: [address, locality]
{authorities}  - id: age-check
    clientIdentifier: haip
    credentials:
      - id: age
        format: dc+sd-jwt
        vctValues: [https://credentials.example.org/national-id]
        claims:
          - path: [birthdate]
    acceptedResponseEncryption: [A256GCM]
  - id: possession-check
    clientIdentifier: haip
    credentials:
      - id: possession
        format: dc+sd-jwt
        vctValues: [https://credentials.example.org/national-id]
{inji_policies}sessions:
  sessionTtlSeconds: 300
  resultTtlSeconds: 1800
  maximumLiveSessions: {capacity}
  maximumHeldPresentationBytes: {held_bytes}
rateLimits:
  sessionCreationsPerPrincipalPerMinute: 1
  sessionCreationBurst: {session_burst}
  walletRequestsPerMinute: 1
  walletRequestBurst: {wallet_burst}
  walletResponsesPerMinute: 1
  walletResponseBurst: {response_burst}
  responsesPerRequestPerMinute: 1
  responseBurstPerRequest: {per_request_burst}
  evidenceReadsPerMinute: 1
  evidenceReadBurst: {read_burst}
",
            secrets = secrets.display(),
            audit = audit_path.display(),
            issuer = idp.issuer(),
            jwks = idp.jwks_uri(),
            kind = options.client_identifier,
            capacity = options.maximum_live_sessions,
            held_bytes = options.maximum_held_presentation_bytes,
            session_burst = options.session_creation_burst,
            wallet_burst = options.wallet_request_burst,
            response_burst = options.wallet_response_burst,
            per_request_burst = options.response_burst_per_request,
            read_burst = options.evidence_read_burst,
        );
        let config_path = dir.path().join("runtime.yaml");
        std::fs::write(&config_path, yaml).unwrap();
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            idp,
            dir,
            keys,
            time: Arc::new(AtomicU64::new(now())),
            config_path,
            audit_path,
        }
    }

    pub fn config(&self) -> Oid4vpConfig {
        Oid4vpConfig::load(&self.config_path).unwrap_or_else(|error| {
            panic!(
                "the test deployment loads: {error} {:?}",
                error.diagnostics()
            )
        })
    }

    pub fn clock(&self) -> Clock {
        let time = Arc::clone(&self.time);
        Arc::new(move || time.load(Ordering::SeqCst))
    }

    pub async fn try_service(&self) -> Result<Arc<VerifierService>, StartupError> {
        VerifierService::load_with_clock(self.config(), self.clock())
            .await
            .map(Arc::new)
    }

    pub async fn service(&self) -> Arc<VerifierService> {
        self.try_service().await.expect("the service starts")
    }

    pub async fn server(&self) -> (TestServer, Arc<VerifierService>) {
        let service = self.service().await;
        (TestServer::new(build_app(Arc::clone(&service))), service)
    }

    /// An access token for `client` carrying `scope`.
    pub fn token(&self, client: &str, subject: &str, scope: &str) -> String {
        self.idp.issue_access_token(
            client,
            subject,
            AUDIENCE,
            scope,
            i64::try_from(now() + 300).unwrap(),
        )
    }

    pub fn applicant_token(&self, client: &str, subject: &str) -> String {
        self.token(client, subject, SESSION_SCOPE)
    }

    /// An access token for the Evidence service credential.
    pub fn evidence_token(&self) -> String {
        self.token("evidence", "evidence-service", READ_SCOPE)
    }

    pub fn audit_journal(&self) -> String {
        std::fs::read_to_string(&self.audit_path).unwrap_or_default()
    }
}

pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}
