#![cfg(unix)]

//! The device-run harness: the wallet journey with a real wallet on a phone.
//!
//! The harness plays the portal and the relying party. It starts the real
//! `evidence-oid4vp` and `evidence` binaries on loopback behind a public HTTPS
//! origin the operator provides (a tunnel or a host forwarding to the listener
//! port), prints the link the wallet opens, waits a bounded time for the
//! presentation, asks Evidence for both definitions, verifies each assertion
//! with the Evidence client, and writes a value-free receipt draft.
//!
//! `a_real_wallet_presents_to_the_verifier` is the device run. It is ignored,
//! never runs in CI, and fails when a `DEVICE_RUN_*` variable is missing or
//! invalid. `a_simulated_wallet_completes_the_device_run_harness` proves the
//! same path without a phone: the simulated wallet of the composed gate stands
//! in for the device while the harness waits.
//!
//! Every key in the simulated test is a fixture generated for the run. The
//! procedure, the variables and the receipt are described in
//! `products/evidence/examples/wallet-presentation/README.md`.

mod common;
#[path = "common/journey.rs"]
mod journey;

use std::{fs, io::Write as _, path::PathBuf, time::Duration};

use journey::{ClientKind, Deployment, Session, Setup, Trust, APPLICANT, IDENTITY, POSSESSION};
use registry_evidence_client::EvidenceClientError;
use registry_platform_crypto::{generate_private_jwk, GeneratedKeyAlgorithm, PrivateJwk};
use serde_json::{json, Value};

/// The receipt schema of a presentation run, beside the OID4VCI receipts under
/// `products/evidence/fixtures/interoperability/`.
const RECEIPT_SCHEMA: &str = "registry.evidence-oid4vp-device-run-receipt/v1";
/// The credential format the verifier requests (`policy::CREDENTIAL_FORMAT`).
const CREDENTIAL_FORMAT: &str = "dc+sd-jwt";
const DEFAULT_TIMEOUT_SECONDS: u64 = 300;
const DEFAULT_MAXIMUM_CREDENTIAL_AGE_SECONDS: u64 = 86_400;

// ---------------------------------------------------------------------------
// Configuration from the environment.
// ---------------------------------------------------------------------------

/// What a person sets for a device run.
struct DeviceConfig {
    public_url: String,
    listen_port: u16,
    client: ClientKind,
    /// `did-web`, `pre-registered` or `x509-san-dns`, as the receipt names it.
    client_kind: &'static str,
    trust: Trust,
    expected_name: String,
    wallet: String,
    wallet_version: String,
    receipt: PathBuf,
    timeout: Duration,
}

/// A variable that must be set and non-blank; a missing one is recorded in
/// `problems` by name.
fn required_variable(
    get: &impl Fn(&str) -> Option<String>,
    name: &str,
    problems: &mut Vec<String>,
) -> String {
    get(name)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            problems.push(format!("{name} is not set"));
            String::new()
        })
}

impl DeviceConfig {
    /// Read the configuration through `get`. Every missing or invalid
    /// variable is reported together, by name and never by value.
    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let mut problems = Vec::new();
        let mut required = |name: &str| required_variable(&get, name, &mut problems);
        let public_url = required("DEVICE_RUN_PUBLIC_URL");
        let listen_port = required("DEVICE_RUN_LISTEN_PORT");
        let kind = required("DEVICE_RUN_CLIENT_IDENTIFIER");
        let issuer = required("DEVICE_RUN_ISSUER");
        let vct = required("DEVICE_RUN_CREDENTIAL_TYPE");
        let jwks_file = required("DEVICE_RUN_ISSUER_JWKS");
        let name_claim = required("DEVICE_RUN_NAME_CLAIM");
        let expected_name = required("DEVICE_RUN_EXPECTED_NAME");
        let wallet = required("DEVICE_RUN_WALLET");
        let wallet_version = required("DEVICE_RUN_WALLET_VERSION");
        let receipt = required("DEVICE_RUN_RECEIPT");

        let public_url = public_url.trim_end_matches('/').to_owned();
        if !public_url.is_empty() {
            match url::Url::parse(&public_url) {
                Ok(parsed)
                    if parsed.scheme() == "https"
                        && parsed.host_str().is_some()
                        && parsed.path() == "/"
                        && parsed.query().is_none() =>
                {
                    // A did:web identifier names the host alone.
                }
                _ => problems.push(
                    "DEVICE_RUN_PUBLIC_URL must be an https origin with no path or query"
                        .to_owned(),
                ),
            }
        }
        let listen_port = if listen_port.is_empty() {
            0
        } else {
            listen_port
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .unwrap_or_else(|| {
                    problems.push("DEVICE_RUN_LISTEN_PORT must be a port number".to_owned());
                    0
                })
        };

        let (client, client_kind) = match kind.as_str() {
            "" => (ClientKind::DidWeb, "did-web"),
            "did-web" => (ClientKind::DidWeb, "did-web"),
            "pre-registered" => {
                let client_id = get("DEVICE_RUN_CLIENT_ID").unwrap_or_default();
                if client_id.trim().is_empty() || client_id.contains(':') {
                    problems.push(
                        "DEVICE_RUN_CLIENT_ID must name the registered client id (no ':') for pre-registered"
                            .to_owned(),
                    );
                }
                (ClientKind::PreRegistered { client_id }, "pre-registered")
            }
            "x509-san-dns" => {
                let chain = get("DEVICE_RUN_X509_CHAIN").unwrap_or_default();
                let key = get("DEVICE_RUN_X509_KEY").unwrap_or_default();
                if chain.is_empty() || key.is_empty() {
                    problems.push(
                        "DEVICE_RUN_X509_CHAIN and DEVICE_RUN_X509_KEY must name the PEM chain and the private JWK files for x509-san-dns"
                            .to_owned(),
                    );
                }
                (
                    ClientKind::X509SanDns {
                        chain: PathBuf::from(chain),
                        key: PathBuf::from(key),
                    },
                    "x509-san-dns",
                )
            }
            _ => {
                problems.push(
                    "DEVICE_RUN_CLIENT_IDENTIFIER must be did-web, pre-registered or x509-san-dns"
                        .to_owned(),
                );
                (ClientKind::DidWeb, "did-web")
            }
        };

        let timeout = match get("DEVICE_RUN_TIMEOUT_SECONDS") {
            None => DEFAULT_TIMEOUT_SECONDS,
            Some(text) => text
                .parse::<u64>()
                .ok()
                .filter(|seconds| (30..=840).contains(seconds))
                .unwrap_or_else(|| {
                    problems
                        .push("DEVICE_RUN_TIMEOUT_SECONDS must be between 30 and 840".to_owned());
                    DEFAULT_TIMEOUT_SECONDS
                }),
        };
        let maximum_age = match get("DEVICE_RUN_MAX_CREDENTIAL_AGE_SECONDS") {
            None => DEFAULT_MAXIMUM_CREDENTIAL_AGE_SECONDS,
            Some(text) => text
                .parse::<u64>()
                .ok()
                .filter(|s| *s > 0)
                .unwrap_or_else(|| {
                    problems.push(
                        "DEVICE_RUN_MAX_CREDENTIAL_AGE_SECONDS must be a positive number"
                            .to_owned(),
                    );
                    DEFAULT_MAXIMUM_CREDENTIAL_AGE_SECONDS
                }),
        };
        if !name_claim.is_empty()
            && !name_claim
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            problems.push(
                "DEVICE_RUN_NAME_CLAIM must be a top-level claim name of letters, digits, '_' and '-'"
                    .to_owned(),
            );
        }
        let keys = if jwks_file.is_empty() {
            Vec::new()
        } else {
            read_issuer_keys(&PathBuf::from(&jwks_file)).unwrap_or_else(|problem| {
                problems.push(problem);
                Vec::new()
            })
        };
        if !problems.is_empty() {
            return Err(format!(
                "the device run is not configured:\n  {}",
                problems.join("\n  ")
            ));
        }
        Ok(Self {
            public_url,
            listen_port,
            client,
            client_kind,
            trust: Trust {
                issuer,
                vct,
                keys,
                name_claim,
                maximum_credential_age_seconds: maximum_age,
            },
            expected_name,
            wallet,
            wallet_version,
            receipt: PathBuf::from(receipt),
            timeout: Duration::from_secs(timeout),
        })
    }

    fn setup(&self) -> Setup {
        Setup {
            public_url: Some(self.public_url.clone()),
            listen_port: Some(self.listen_port),
            client: self.client.clone(),
            trust: Some(self.trust.clone()),
            session_ttl_seconds: Some(self.timeout.as_secs() + 60),
        }
    }
}

/// The public keys in a JWKS file, or in a file holding one JWK. A private
/// member is refused: the file is copied into the deployment's trust
/// configuration.
fn read_issuer_keys(path: &std::path::Path) -> Result<Vec<Value>, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("DEVICE_RUN_ISSUER_JWKS cannot be read: {error}"))?;
    let document: Value =
        serde_json::from_str(&text).map_err(|_| "DEVICE_RUN_ISSUER_JWKS is not JSON".to_owned())?;
    let keys = match document.get("keys").and_then(Value::as_array) {
        Some(keys) => keys.clone(),
        None if document.get("kty").is_some() => vec![document],
        None => return Err("DEVICE_RUN_ISSUER_JWKS holds neither a JWKS nor a JWK".to_owned()),
    };
    if keys.is_empty() {
        return Err("DEVICE_RUN_ISSUER_JWKS holds no key".to_owned());
    }
    if keys.iter().any(|key| key.get("d").is_some()) {
        return Err(
            "DEVICE_RUN_ISSUER_JWKS holds a private key; supply the public keys only".to_owned(),
        );
    }
    Ok(keys)
}

// ---------------------------------------------------------------------------
// The run.
// ---------------------------------------------------------------------------

/// Who presents the credential.
enum Presenter<'a> {
    /// A person with a phone, who opens the printed link.
    Phone,
    /// The composed gate's simulated wallet, with the issuer key it signs with
    /// and the name it discloses.
    Simulated {
        issuer: &'a PrivateJwk,
        name: &'a str,
    },
}

/// How one definition went. Nothing here is a claim value, token or reference.
struct DefinitionOutcome {
    id: &'static str,
    passed: bool,
    failing_stage: Option<&'static str>,
}

struct Definition {
    id: &'static str,
    policy: &'static str,
    requirement: &'static str,
    discloses_name: bool,
}

const DEFINITIONS: [Definition; 2] = [
    Definition {
        id: "credential-possession",
        policy: "credential-possession",
        requirement: POSSESSION,
        discloses_name: false,
    },
    Definition {
        id: "identity-match",
        policy: "identity-match",
        requirement: IDENTITY,
        discloses_name: true,
    },
];

/// Run one definition: a session, the presentation, the Evidence request and
/// the relying party's verification. `witnessed` collects the identifiers of
/// the run so a test can prove the receipt holds none of them.
async fn run_definition(
    deployment: &Deployment,
    config: &DeviceConfig,
    definition: &Definition,
    presenter: &Presenter<'_>,
    witnessed: &mut Vec<String>,
) -> DefinitionOutcome {
    let fail = |stage| DefinitionOutcome {
        id: definition.id,
        passed: false,
        failing_stage: Some(stage),
    };
    let session = deployment
        .create_session(APPLICANT, definition.policy)
        .await;
    witnessed.extend([
        session.reference.clone(),
        session.request_id.clone(),
        session.request_uri.clone(),
        session.wallet_invocation.clone(),
    ]);
    announce(definition, &session);
    if let Presenter::Simulated { issuer, name } = presenter {
        let claims: Vec<(&str, &str)> = if definition.discloses_name {
            vec![(config.trust.name_claim.as_str(), *name)]
        } else {
            Vec::new()
        };
        deployment.present(&session, issuer, &claims).await;
    }
    match deployment
        .wait_for_presentation(&session, config.timeout)
        .await
        .as_str()
    {
        "received" => {}
        "failed" => return fail("verifier-rejected-presentation"),
        _ => return fail("presentation-not-received"),
    }
    let expected = definition
        .discloses_name
        .then_some(config.expected_name.as_str());
    match deployment
        .request(definition.requirement, &session, APPLICANT, expected)
        .await
    {
        Ok(verified) => match journey::boolean_output(&verified) {
            Some(true) => DefinitionOutcome {
                id: definition.id,
                passed: true,
                failing_stage: None,
            },
            Some(false) => fail("assertion-false"),
            None => fail("assertion-shape"),
        },
        // The service collapses every credential refusal into one dependency
        // failure; the verifier and Evidence logs hold the cause.
        Err(EvidenceClientError::Unavailable { .. }) => fail("evidence-refused"),
        Err(_) => fail("assertion-verification"),
    }
}

/// What the operator needs to open the wallet. The link is a one-use session
/// bearer, printed and never recorded in the receipt.
fn announce(definition: &Definition, session: &Session) {
    println!("\n== {} ==", definition.id);
    println!("Open this link in the wallet (render it as a QR code with `qrencode -t ANSIUTF8`):");
    println!("{}", session.wallet_invocation);
    println!("Request URI: {}", session.request_uri);
    if definition.discloses_name {
        println!("Approve disclosure of the name claim.");
    } else {
        println!("The wallet should present without disclosing a claim.");
    }
}

/// The date `seconds` since the epoch falls on, in UTC.
fn utc_date(seconds: u64) -> String {
    let seconds = i64::try_from(seconds).expect("the time fits");
    chrono::DateTime::from_timestamp(seconds, 0)
        .expect("the time is in range")
        .format("%Y-%m-%d")
        .to_string()
}

/// The value-free receipt draft.
fn receipt(config: &DeviceConfig, outcomes: &[DefinitionOutcome]) -> Value {
    let result = if outcomes.iter().all(|outcome| outcome.passed) {
        "pass"
    } else {
        "fail"
    };
    json!({
        "schema": RECEIPT_SCHEMA,
        "status": "draft",
        "testedOn": utc_date(common::now()),
        "wallet": {"label": config.wallet, "version": config.wallet_version},
        "clientIdentifier": {"kind": config.client_kind},
        "responseMode": "direct_post.jwt",
        "credentialFormat": CREDENTIAL_FORMAT,
        "result": result,
        "definitions": outcomes
            .iter()
            .map(|outcome| json!({
                "id": outcome.id,
                "outcome": if outcome.passed { "pass" } else { "fail" },
                "failingStage": outcome.failing_stage,
            }))
            .collect::<Vec<_>>(),
        "claimBoundary": "One run of one wallet version against one verifier deployment. It is not certification, another wallet version, or general compatibility. A draft is not evidence until a person reviews it and commits it.",
    })
}

/// Run both definitions and return the receipt draft and the identifiers the
/// run generated.
async fn execute(
    deployment: &Deployment,
    config: &DeviceConfig,
    presenter: &Presenter<'_>,
) -> (Value, Vec<String>) {
    let mut witnessed = Vec::new();
    let mut outcomes = Vec::new();
    for definition in &DEFINITIONS {
        let outcome =
            run_definition(deployment, config, definition, presenter, &mut witnessed).await;
        println!(
            "{}: {}{}",
            outcome.id,
            if outcome.passed { "pass" } else { "fail" },
            outcome
                .failing_stage
                .map_or_else(String::new, |stage| format!(" (stage: {stage})"))
        );
        outcomes.push(outcome);
    }
    (receipt(config, &outcomes), witnessed)
}

/// Write the draft to the path the person named. An existing file is never
/// replaced.
fn write_receipt(path: &std::path::Path, receipt: &Value) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|error| {
            panic!(
                "the receipt draft cannot be created at {}: {error}",
                path.display()
            )
        });
    let mut text = serde_json::to_string_pretty(receipt).expect("the receipt encodes");
    text.push('\n');
    file.write_all(text.as_bytes())
        .expect("the receipt draft is written");
    println!("Receipt draft written to {}", path.display());
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// The committed receipt format.
fn receipt_schema() -> jsonschema::JSONSchema {
    let path = journey::example_dir()
        .join("../../fixtures/interoperability/oid4vp-device-run/receipt.schema.json");
    let schema: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("the receipt schema is readable"))
            .expect("the receipt schema is JSON");
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("the receipt schema compiles")
}

fn assert_receipt_valid(receipt: &Value) {
    if let Err(errors) = receipt_schema().validate(receipt) {
        let reasons: Vec<String> = errors.map(|error| error.to_string()).collect();
        panic!("the receipt is invalid: {reasons:?}");
    }
}

#[test]
fn a_failed_run_makes_a_valid_receipt_with_its_failing_stage() {
    let dir = common::canonical_tempdir();
    let values = complete_values(dir.path());
    let config =
        DeviceConfig::from_lookup(lookup(&values)).unwrap_or_else(|error| panic!("{error}"));
    let outcomes = [
        DefinitionOutcome {
            id: "credential-possession",
            passed: true,
            failing_stage: None,
        },
        DefinitionOutcome {
            id: "identity-match",
            passed: false,
            failing_stage: Some("presentation-not-received"),
        },
    ];
    let draft = receipt(&config, &outcomes);
    assert_receipt_valid(&draft);
    assert_eq!(draft["result"], "fail");
    assert_eq!(
        draft["definitions"][1]["failingStage"],
        "presentation-not-received"
    );
    // The environment's values never reach the receipt.
    let text = draft.to_string();
    for value in [
        "expected-name-canary",
        "issuer.example.net",
        "verifier.example.net",
    ] {
        assert!(!text.contains(value), "{value} reached the receipt");
    }
}

#[test]
fn the_receipt_format_refuses_a_value_or_an_unknown_stage() {
    let dir = common::canonical_tempdir();
    let values = complete_values(dir.path());
    let config =
        DeviceConfig::from_lookup(lookup(&values)).unwrap_or_else(|error| panic!("{error}"));
    let outcomes = [
        DefinitionOutcome {
            id: "credential-possession",
            passed: true,
            failing_stage: None,
        },
        DefinitionOutcome {
            id: "identity-match",
            passed: true,
            failing_stage: None,
        },
    ];
    let valid = receipt(&config, &outcomes);
    assert_receipt_valid(&valid);
    let schema = receipt_schema();
    let mut extra = valid.clone();
    extra["name"] = json!("a value");
    assert!(!schema.is_valid(&extra));
    let mut stage = valid.clone();
    stage["definitions"][0]["failingStage"] = json!("something-else");
    assert!(!schema.is_valid(&stage));
    let mut mode = valid;
    mode["responseMode"] = json!("direct_post");
    assert!(!schema.is_valid(&mode));
}

fn lookup<'a>(values: &'a [(&'a str, String)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |name| {
        values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.clone())
    }
}

fn complete_values(dir: &std::path::Path) -> Vec<(&'static str, String)> {
    let jwks = dir.join("issuer-jwks.json");
    fs::write(
        &jwks,
        json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k", "x": "AAAA"}]}).to_string(),
    )
    .expect("the key set is written");
    vec![
        (
            "DEVICE_RUN_PUBLIC_URL",
            "https://verifier.example.net/".to_owned(),
        ),
        ("DEVICE_RUN_LISTEN_PORT", "8095".to_owned()),
        ("DEVICE_RUN_CLIENT_IDENTIFIER", "did-web".to_owned()),
        ("DEVICE_RUN_ISSUER", "https://issuer.example.net".to_owned()),
        (
            "DEVICE_RUN_CREDENTIAL_TYPE",
            "https://credentials.example.net/t".to_owned(),
        ),
        ("DEVICE_RUN_ISSUER_JWKS", jwks.display().to_string()),
        ("DEVICE_RUN_NAME_CLAIM", "name".to_owned()),
        (
            "DEVICE_RUN_EXPECTED_NAME",
            "expected-name-canary".to_owned(),
        ),
        ("DEVICE_RUN_WALLET", "Example Wallet".to_owned()),
        ("DEVICE_RUN_WALLET_VERSION", "1.2.3".to_owned()),
        (
            "DEVICE_RUN_RECEIPT",
            dir.join("receipt.json").display().to_string(),
        ),
    ]
}

#[test]
fn a_complete_environment_configures_the_run() {
    let dir = common::canonical_tempdir();
    let values = complete_values(dir.path());
    let config =
        DeviceConfig::from_lookup(lookup(&values)).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(config.public_url, "https://verifier.example.net");
    assert_eq!(config.listen_port, 8095);
    assert_eq!(config.client_kind, "did-web");
    assert_eq!(config.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECONDS));
    assert_eq!(config.trust.keys.len(), 1);
}

#[test]
fn a_missing_variable_fails_by_name_without_echoing_any_value() {
    let dir = common::canonical_tempdir();
    let mut values = complete_values(dir.path());
    values.retain(|(name, _)| {
        ![
            "DEVICE_RUN_WALLET",
            "DEVICE_RUN_EXPECTED_NAME",
            "DEVICE_RUN_PUBLIC_URL",
        ]
        .contains(name)
    });
    let error = DeviceConfig::from_lookup(lookup(&values))
        .err()
        .expect("an incomplete environment is refused");
    for name in [
        "DEVICE_RUN_WALLET",
        "DEVICE_RUN_EXPECTED_NAME",
        "DEVICE_RUN_PUBLIC_URL",
    ] {
        assert!(error.contains(&format!("{name} is not set")), "{error}");
    }
    assert!(!error.contains("expected-name-canary"), "{error}");
}

#[test]
fn an_invalid_variable_is_refused() {
    let dir = common::canonical_tempdir();
    for (name, value, fragment) in [
        (
            "DEVICE_RUN_PUBLIC_URL",
            "http://verifier.example.net",
            "https origin",
        ),
        (
            "DEVICE_RUN_PUBLIC_URL",
            "https://verifier.example.net/path",
            "https origin",
        ),
        ("DEVICE_RUN_LISTEN_PORT", "0", "port number"),
        (
            "DEVICE_RUN_CLIENT_IDENTIFIER",
            "x509-hash",
            "did-web, pre-registered or x509-san-dns",
        ),
        ("DEVICE_RUN_TIMEOUT_SECONDS", "5", "between 30 and 840"),
        ("DEVICE_RUN_NAME_CLAIM", "a\"]; x", "letters, digits"),
    ] {
        let mut values = complete_values(dir.path());
        values.retain(|(key, _)| *key != name);
        values.push((name, value.to_owned()));
        let error = DeviceConfig::from_lookup(lookup(&values))
            .err()
            .unwrap_or_else(|| panic!("{name}={value} is accepted"));
        assert!(error.contains(fragment), "{name}: {error}");
    }
    // A pre-registered identifier needs a bare client id; an X.509 one needs
    // both files.
    let mut values = complete_values(dir.path());
    values.retain(|(key, _)| *key != "DEVICE_RUN_CLIENT_IDENTIFIER");
    values.push(("DEVICE_RUN_CLIENT_IDENTIFIER", "pre-registered".to_owned()));
    assert!(DeviceConfig::from_lookup(lookup(&values)).is_err());
    values.push(("DEVICE_RUN_CLIENT_ID", "evidence-verifier".to_owned()));
    assert!(DeviceConfig::from_lookup(lookup(&values)).is_ok());
    values.retain(|(key, _)| *key != "DEVICE_RUN_CLIENT_IDENTIFIER");
    values.push(("DEVICE_RUN_CLIENT_IDENTIFIER", "x509-san-dns".to_owned()));
    assert!(DeviceConfig::from_lookup(lookup(&values)).is_err());
}

#[test]
fn a_private_issuer_key_is_refused() {
    let dir = common::canonical_tempdir();
    let mut values = complete_values(dir.path());
    let path = dir.path().join("private.json");
    fs::write(
        &path,
        json!({"kty": "OKP", "crv": "Ed25519", "x": "AAAA", "d": "BBBB"}).to_string(),
    )
    .expect("the key is written");
    values.retain(|(key, _)| *key != "DEVICE_RUN_ISSUER_JWKS");
    values.push(("DEVICE_RUN_ISSUER_JWKS", path.display().to_string()));
    let error = DeviceConfig::from_lookup(lookup(&values))
        .err()
        .expect("a private key is refused");
    assert!(error.contains("private key"), "{error}");
    assert!(!error.contains("BBBB"), "{error}");
}

#[test]
fn an_existing_receipt_is_never_replaced() {
    let dir = common::canonical_tempdir();
    let path = dir.path().join("receipt.json");
    fs::write(&path, "earlier").expect("an earlier file");
    let result = std::panic::catch_unwind(|| write_receipt(&path, &json!({})));
    assert!(result.is_err());
    assert_eq!(fs::read_to_string(&path).expect("read"), "earlier");
}

/// The device run. Needs a phone, a wallet holding an SD-JWT VC from the
/// trusted issuer, a public HTTPS origin forwarding to the listener port, and
/// the `DEVICE_RUN_*` variables the README lists. Run with `--nocapture` to see
/// the link.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "device run: needs a real wallet, a public HTTPS origin, EVIDENCE_BIN, EVIDENCECTL_BIN and the DEVICE_RUN_* variables; see products/evidence/examples/wallet-presentation/README.md"]
async fn a_real_wallet_presents_to_the_verifier() {
    let config = DeviceConfig::from_lookup(|name| std::env::var(name).ok())
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        !config.receipt.exists(),
        "{} exists; name a new receipt path",
        config.receipt.display()
    );
    let deployment = Deployment::start(config.setup()).await;
    println!(
        "Verifier listening on 127.0.0.1:{}; the public origin {} must forward to it.",
        config.listen_port, config.public_url
    );
    let (draft, _) = execute(&deployment, &config, &Presenter::Phone).await;
    write_receipt(&config.receipt, &draft);
    assert_eq!(
        draft["result"], "pass",
        "the run did not pass; see the receipt draft"
    );
}

/// The harness path without a phone.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "exact gate: starts the real evidence-oid4vp and evidence binaries on loopback; needs EVIDENCE_BIN and EVIDENCECTL_BIN"]
async fn a_simulated_wallet_completes_the_device_run_harness() {
    const NAME: &str = "Zoë Ångström-Nyström";
    let dir = common::canonical_tempdir();
    let generated = generate_private_jwk(GeneratedKeyAlgorithm::Ed25519).expect("an issuer key");
    let issuer: PrivateJwk = serde_json::from_value(json!({
        "kty": generated.kty, "crv": generated.crv, "alg": generated.alg,
        "kid": "device-run-issuer-key", "x": generated.x, "d": generated.d,
    }))
    .expect("the issuer key parses");
    let jwks = dir.path().join("issuer-jwks.json");
    fs::write(
        &jwks,
        json!({"keys": [{
            "kty": issuer.kty, "crv": issuer.crv, "kid": "device-run-issuer-key", "x": issuer.x,
        }]})
        .to_string(),
    )
    .expect("the key set is written");
    let receipt_path = dir.path().join("receipt.json");
    let values = vec![
        (
            "DEVICE_RUN_PUBLIC_URL",
            "https://verifier.example.net".to_owned(),
        ),
        ("DEVICE_RUN_LISTEN_PORT", journey::free_port().to_string()),
        ("DEVICE_RUN_CLIENT_IDENTIFIER", "did-web".to_owned()),
        (
            "DEVICE_RUN_ISSUER",
            "https://device-issuer.example.net".to_owned(),
        ),
        (
            "DEVICE_RUN_CREDENTIAL_TYPE",
            "https://credentials.example.net/device".to_owned(),
        ),
        ("DEVICE_RUN_ISSUER_JWKS", jwks.display().to_string()),
        ("DEVICE_RUN_NAME_CLAIM", "full_name".to_owned()),
        (
            "DEVICE_RUN_EXPECTED_NAME",
            "zoe angstrom nystrom".to_owned(),
        ),
        ("DEVICE_RUN_WALLET", "Simulated wallet".to_owned()),
        ("DEVICE_RUN_WALLET_VERSION", "0".to_owned()),
        ("DEVICE_RUN_RECEIPT", receipt_path.display().to_string()),
        ("DEVICE_RUN_TIMEOUT_SECONDS", "30".to_owned()),
    ];
    let config =
        DeviceConfig::from_lookup(lookup(&values)).unwrap_or_else(|error| panic!("{error}"));

    let deployment = Deployment::start(config.setup()).await;
    let presenter = Presenter::Simulated {
        issuer: &issuer,
        name: NAME,
    };
    let (draft, witnessed) = execute(&deployment, &config, &presenter).await;
    write_receipt(&config.receipt, &draft);

    let text = fs::read_to_string(&receipt_path).expect("the receipt draft is readable");
    let written: Value = serde_json::from_str(&text).expect("the receipt draft is JSON");
    assert_receipt_valid(&written);
    assert_eq!(written["schema"], RECEIPT_SCHEMA);
    assert_eq!(written["status"], "draft");
    assert_eq!(written["result"], "pass", "{written}");
    assert_eq!(
        written["wallet"],
        json!({"label": "Simulated wallet", "version": "0"})
    );
    assert_eq!(written["clientIdentifier"], json!({"kind": "did-web"}));
    assert_eq!(written["responseMode"], "direct_post.jwt");
    assert_eq!(written["credentialFormat"], "dc+sd-jwt");
    assert_eq!(
        written["definitions"],
        json!([
            {"id": "credential-possession", "outcome": "pass", "failingStage": null},
            {"id": "identity-match", "outcome": "pass", "failingStage": null},
        ])
    );
    assert_eq!(witnessed.len(), 8, "two sessions, four identifiers each");
    let mut forbidden = witnessed;
    forbidden.extend(
        [
            NAME,
            "zoe angstrom nystrom",
            "full_name",
            "device-issuer.example.net",
            "device-run-issuer-key",
            "verifier.example.net",
        ]
        .map(str::to_owned),
    );
    for value in forbidden {
        assert!(!text.contains(&value), "the receipt holds a run value");
    }
}
