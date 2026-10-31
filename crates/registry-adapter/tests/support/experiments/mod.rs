// SPDX-License-Identifier: Apache-2.0

//! Native acceptance harness for the five authored API experiments.

pub mod upstream;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
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
use upstream::{Response, Upstream};

const ISSUER: &str = "http://127.0.0.1:9";
const AUDIENCE: &str = "registry-adapter-experiment-test";
const SUBJECT: &str = "synthetic-experiment-caller";
const CLIENT_ID: &str = "synthetic-client";
const OAUTH_CLIENT_ID: &str = "synthetic-upstream-client";
const OAUTH_CLIENT_SECRET: &str = "synthetic-upstream-secret";
const API_KEY: &str = "synthetic-graphql-api-key";
const ACCESS_TOKEN: &str = "synthetic-replay-token";
const CURSOR_KEY: &str = "synthetic-cursor-key-0123456789!";
const ASSERTION_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#;

static NEXT_SCHEMA: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scenario {
    FhirPatient,
    FhirConditionalCreate,
    GraphQlCases,
    RestMutualTls,
    SecondProfile,
}

impl Scenario {
    pub fn slug(self) -> &'static str {
        match self {
            Self::FhirPatient => "fhir-r4-patient-source",
            Self::FhirConditionalCreate => "fhir-r4-conditional-create",
            Self::GraphQlCases => "graphql-cursor-source",
            Self::RestMutualTls => "rest-offset-mtls",
            Self::SecondProfile => "second-target-profile",
        }
    }

    pub fn scope(self) -> &'static str {
        match self {
            Self::FhirConditionalCreate => "records.write",
            Self::GraphQlCases => "cases.read",
            Self::SecondProfile => "system/Basic.read",
            Self::FhirPatient | Self::RestMutualTls => "records.read",
        }
    }

    fn profile(self) -> PathBuf {
        match self {
            Self::GraphQlCases => product_root().join("profiles/case-api/profile.yaml"),
            Self::SecondProfile => self.directory().join("profile.yaml"),
            _ => product_root().join("profiles/breg-records/profile.yaml"),
        }
    }

    fn pack(self) -> PathBuf {
        self.directory().join("pack.yaml")
    }

    pub fn directory(self) -> PathBuf {
        product_root().join("experiments").join(self.slug())
    }

    fn fixture_path(self) -> PathBuf {
        let fixtures = self.directory().join("fixtures");
        let mut paths: Vec<PathBuf> = std::fs::read_dir(fixtures)
            .expect("read the experiment fixtures")
            .map(|entry| entry.expect("fixture entry").path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "yaml")
            })
            .collect();
        paths.sort();
        assert_eq!(paths.len(), 1, "one documented fixture per experiment");
        paths.pop().expect("one fixture")
    }

    fn base_path(self) -> &'static str {
        match self {
            Self::FhirPatient | Self::FhirConditionalCreate => "/baseR4",
            Self::GraphQlCases => "/graphql",
            Self::RestMutualTls | Self::SecondProfile => "/api",
        }
    }

    fn verify_wait(self) -> (usize, &'static str) {
        match self {
            Self::FhirPatient | Self::FhirConditionalCreate => (1, "caller-sourced"),
            // The authored error-handling control flow prevents verify from
            // proving which GraphQL send runs without a facade exchange.
            Self::GraphQlCases => (2, "caller-sourced"),
            // Both bindings read exchange state before the engine reaches the
            // mTLS transport. The native path below separately proves mTLS.
            Self::RestMutualTls | Self::SecondProfile => (2, "caller-sourced"),
        }
    }

    fn is_mutual_tls(self) -> bool {
        matches!(self, Self::RestMutualTls | Self::SecondProfile)
    }
}

fn product_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter")
}

/// The committed documented fixture, consumed without inventing source data.
pub struct Fixture {
    document: Value,
}

impl Fixture {
    #[allow(clippy::disallowed_methods)]
    pub fn load(scenario: Scenario) -> Self {
        let text = std::fs::read_to_string(scenario.fixture_path())
            .expect("read the committed experiment fixture");
        Self {
            document: serde_norway::from_str(&text).expect("fixture is YAML"),
        }
    }

    pub fn request(&self) -> &Value {
        &self.entry()["facadeRequest"]
    }

    pub fn expected(&self) -> &Value {
        &self.entry()["expected"]
    }

    fn entry(&self) -> &Value {
        let entries = self.document["entries"]
            .as_array()
            .expect("fixture entries");
        assert_eq!(entries.len(), 1, "one fixture entry is driven natively");
        &entries[0]
    }

    fn exchanges(&self) -> &[Value] {
        self.entry()["upstream"]
            .as_array()
            .expect("fixture upstream exchanges")
    }

    pub fn responses(&self) -> Vec<Response> {
        self.exchanges()
            .iter()
            .map(|exchange| Response {
                status: u16::try_from(
                    exchange["response"]["status"]
                        .as_u64()
                        .expect("response status"),
                )
                .expect("response status fits u16"),
                body: exchange["response"]["body"].to_string(),
            })
            .collect()
    }
}

/// One native adapter process built by Cargo for this test target.
pub struct NativeExperiment {
    scenario: Scenario,
    child: Child,
    port: u16,
    key: registry_platform_crypto::PrivateJwk,
    runtime: PathBuf,
    environment: BTreeMap<String, String>,
    _directory: tempfile::TempDir,
}

impl Drop for NativeExperiment {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl NativeExperiment {
    pub async fn start(scenario: Scenario, upstream: &Upstream) -> Self {
        assert_eq!(
            scenario.is_mutual_tls(),
            upstream.ca_bundle_path().is_some()
        );
        let database = schema_url().await;
        let key = access_token_test_key(jsonwebtoken::Algorithm::ES256);
        let jwks = jwks_from_private_jwk(&key).to_string();
        let port = free_port();
        let directory = tempfile::tempdir().expect("experiment runtime scratch directory");
        let runtime = directory.path().join("runtime.yaml");
        let endpoint_yaml = endpoint_yaml(scenario, upstream);
        let tls_yaml = upstream
            .ca_bundle_path()
            .map_or_else(String::new, |bundle| {
                format!(
                    "outboundTls:\n  trustProfiles:\n    experiment-ca:\n      caBundleFile: {}\n",
                    bundle.display()
                )
            });
        std::fs::write(
            &runtime,
            format!(
                r#"apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: experiment-{slug}
endpoints:
{endpoint_yaml}listener:
  bind: 127.0.0.1:{port}
database:
  runtimeUrlRef: secret:env/EXPERIMENT_DB_URL
  migrationUrlRef: secret:env/EXPERIMENT_DB_URL
  testOnlyPlaintext: true
oidc:
  issuer: {ISSUER}
  audience: {AUDIENCE}
  allowInsecureHttp: true
  jwksSource:
    type: static
    documentRef: secret:env/EXPERIMENT_JWKS
allowedClients:
  - {CLIENT_ID}
allowedPrivateCidrs:
  - 192.168.0.0/16
audit:
  retentionDays: 90
idempotency:
  responseRetentionSeconds: 86400
cursorKeyRef: secret:env/EXPERIMENT_CURSOR_KEY
{tls_yaml}"#,
                slug = scenario.slug(),
            ),
        )
        .expect("write the experiment runtime");

        let mut environment = BTreeMap::from([
            ("EXPERIMENT_DB_URL".to_owned(), database),
            ("EXPERIMENT_JWKS".to_owned(), jwks),
            ("EXPERIMENT_CURSOR_KEY".to_owned(), CURSOR_KEY.to_owned()),
            (
                "EXPERIMENT_OAUTH_CLIENT_ID".to_owned(),
                OAUTH_CLIENT_ID.to_owned(),
            ),
            (
                "EXPERIMENT_OAUTH_CLIENT_SECRET".to_owned(),
                OAUTH_CLIENT_SECRET.to_owned(),
            ),
            ("EXPERIMENT_API_KEY".to_owned(), API_KEY.to_owned()),
            (
                "EXPERIMENT_ASSERTION_JWK".to_owned(),
                ASSERTION_JWK.to_owned(),
            ),
        ]);
        if let (Some(certificate), Some(private_key)) =
            (upstream.client_certificate_pem(), upstream.client_key_pem())
        {
            environment.insert(
                "EXPERIMENT_MTLS_CERTIFICATE".to_owned(),
                certificate.to_owned(),
            );
            environment.insert("EXPERIMENT_MTLS_KEY".to_owned(), private_key.to_owned());
        }

        let mut command = Command::new(env!("CARGO_BIN_EXE_adapter"));
        command
            .args(["serve", "--runtime-config"])
            .arg(&runtime)
            .arg("--project")
            .arg(scenario.directory())
            .arg("--profile")
            .arg(scenario.profile())
            .arg("--pack")
            .arg(scenario.pack())
            .envs(&environment)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let child = command.spawn().expect("start the native adapter binary");
        let mut served = Self {
            scenario,
            child,
            port,
            key,
            runtime,
            environment,
            _directory: directory,
        };
        served.wait_until_listening();
        served
    }

    pub fn run_cli_acceptance(&self, fixture: &Fixture) {
        let check = self.adapterctl(&[
            "check",
            self.scenario.directory().to_str().expect("experiment path"),
            "--profile",
            self.scenario.profile().to_str().expect("profile path"),
            "--pack",
            self.scenario.pack().to_str().expect("pack path"),
            "--runtime",
            self.runtime.to_str().expect("runtime path"),
            "--environment",
        ]);
        assert_eq!(check["command"], "check", "{check}");
        assert_eq!(check["status"], "complete", "{check}");
        assert_eq!(check["diagnostics"], json!([]), "{check}");

        let replay = self.adapterctl(&[
            "fixtures",
            "replay",
            self.scenario.directory().to_str().expect("experiment path"),
            "--profile",
            self.scenario.profile().to_str().expect("profile path"),
            "--pack",
            self.scenario.pack().to_str().expect("pack path"),
        ]);
        assert_eq!(replay["command"], "fixtures replay", "{replay}");
        assert_eq!(replay["status"], "complete", "{replay}");
        assert_eq!(replay["drive"], "completed", "{replay}");
        assert_eq!(replay["entries"], 1, "{replay}");
        assert_eq!(
            replay["upstreamExchanges"],
            fixture.exchanges().len(),
            "{replay}"
        );

        let verify = self.adapterctl(&[
            "verify",
            "--live",
            self.scenario.directory().to_str().expect("experiment path"),
            "--runtime",
            self.runtime.to_str().expect("runtime path"),
            "--profile",
            self.scenario.profile().to_str().expect("profile path"),
            "--pack",
            self.scenario.pack().to_str().expect("pack path"),
        ]);
        let (waited, reason) = self.scenario.verify_wait();
        assert_eq!(verify["command"], "verify", "{verify}");
        assert_eq!(verify["status"], "complete", "{verify}");
        assert_eq!(verify["drove"], 0, "a wait is not a probe: {verify}");
        assert_eq!(verify["waited"], waited, "{verify}");
        assert!(
            verify["waits"]
                .as_array()
                .is_some_and(|waits| waits.len() == waited
                    && waits.iter().all(|wait| wait["reason"] == reason)),
            "{verify}"
        );
    }

    pub fn call(&self, fixture: &Fixture) -> (u16, String, Value) {
        self.call_with_bearer(fixture, &self.token(self.scenario.scope()))
    }

    pub fn assert_forged_token_rejected(&self, fixture: &Fixture, upstream: &Upstream) {
        let other = access_token_test_key(jsonwebtoken::Algorithm::ES256);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let forged = sign_compact_jwt_with_key(
            &other,
            "at+jwt",
            "untrusted-experiment-key",
            json!({
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": SUBJECT,
                "client_id": CLIENT_ID,
                "scope": self.scenario.scope(),
                "iat": now,
                "nbf": now,
                "exp": now + 300,
                "jti": format!("forged-{now}"),
            }),
        );
        let response = self.call_with_bearer(fixture, &forged);
        assert_eq!(response.0, 401, "{}", response.2);
        assert!(
            upstream.requests().is_empty(),
            "JWT verification precedes every upstream effect"
        );
    }

    fn call_with_bearer(&self, fixture: &Fixture, token: &str) -> (u16, String, Value) {
        let request = fixture.request();
        let method = request["path"]
            .as_str()
            .and_then(|_| request["operation"].as_str())
            .map(|operation| {
                if operation == "records-create" || operation == "cases-find" {
                    "POST"
                } else {
                    "GET"
                }
            })
            .expect("fixture operation");
        let mut target = request["path"].as_str().expect("facade path").to_owned();
        if let Some(query) = request.get("query").and_then(Value::as_str) {
            target.push('?');
            target.push_str(query);
        }
        let body = request
            .get("body")
            .filter(|body| !body.is_null())
            .map(Value::to_string)
            .unwrap_or_default();
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect facade");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("facade read timeout");
        let mut wire = format!(
            "{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n"
        );
        if let Some(headers) = request.get("headers").and_then(Value::as_object) {
            for (name, value) in headers {
                wire.push_str(&format!(
                    "{name}: {}\r\n",
                    value.as_str().expect("fixture header is text")
                ));
            }
        }
        if !body.is_empty()
            && request["headers"].as_object().is_none_or(|headers| {
                !headers
                    .keys()
                    .any(|name| name.eq_ignore_ascii_case("content-type"))
            })
        {
            wire.push_str("Content-Type: application/json\r\n");
        }
        if !body.is_empty() {
            wire.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        wire.push_str("\r\n");
        stream
            .write_all(wire.as_bytes())
            .expect("write facade head");
        stream
            .write_all(body.as_bytes())
            .expect("write facade body");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).expect("read facade answer");
        let text = String::from_utf8(raw).expect("facade answer is UTF-8");
        let (head, body) = text.split_once("\r\n\r\n").expect("facade head");
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("facade status");
        let body = serde_json::from_str(body.trim()).expect("facade JSON body");
        (status, head.to_owned(), body)
    }

    fn adapterctl(&self, arguments: &[&str]) -> Value {
        let binary = std::env::var("ADAPTERCTL_BIN")
            .expect("test-postgres.sh must provide the native ADAPTERCTL_BIN");
        let output = Command::new(binary)
            .arg("--format=json")
            .args(arguments)
            .envs(&self.environment)
            .output()
            .expect("run the native adapterctl binary");
        assert!(
            output.status.success(),
            "adapterctl {arguments:?} failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("adapterctl JSON report")
    }

    fn token(&self, scope: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        sign_compact_jwt_with_key(
            &self.key,
            "at+jwt",
            "canary-resource-key",
            json!({
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": SUBJECT,
                "client_id": CLIENT_ID,
                "scope": scope,
                "iat": now,
                "nbf": now,
                "exp": now + 300,
                "jti": format!("experiment-{now}-{}", NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)),
            }),
        )
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
}

fn endpoint_yaml(scenario: Scenario, upstream: &Upstream) -> String {
    match scenario {
        Scenario::FhirPatient | Scenario::FhirConditionalCreate => format!(
            "  - endpoint: fhir\n    baseUrl: {}\n    credential:\n      type: oauth2-client-credentials\n      tokenEndpoint: {}\n      clientIdRef: secret:env/EXPERIMENT_OAUTH_CLIENT_ID\n      clientSecretRef: secret:env/EXPERIMENT_OAUTH_CLIENT_SECRET\n      scope: {}\n      credentialPlacement: basic-header\n      maximumCacheSeconds: 300\n",
            upstream.url(scenario.base_path()),
            upstream.url("/oauth/token"),
            if scenario == Scenario::FhirPatient {
                "system/Patient.read"
            } else {
                "system/Patient.write system/Patient.read"
            }
        ),
        Scenario::GraphQlCases => ["cases-query", "case-node"]
            .into_iter()
            .map(|endpoint| {
                format!(
                    "  - endpoint: {endpoint}\n    baseUrl: {}\n    credential:\n      type: static-api-key\n      valueRef: secret:env/EXPERIMENT_API_KEY\n",
                    upstream.url(scenario.base_path())
                )
            })
            .collect(),
        Scenario::RestMutualTls | Scenario::SecondProfile => {
            let token_endpoint = upstream.url("/oauth/token");
            format!(
                "  - endpoint: registry\n    baseUrl: {}\n    credential:\n      type: oauth2-private-key-jwt\n      tokenEndpoint: {token_endpoint}\n      clientIdRef: secret:env/EXPERIMENT_OAUTH_CLIENT_ID\n      clientAssertionKeyRef: secret:env/EXPERIMENT_ASSERTION_JWK\n      clientAssertionAudience: {token_endpoint}\n      scope: households.read\n      maximumCacheSeconds: 300\n    tlsTrustProfile: experiment-ca\n    mtlsIdentity:\n      certificateRef: secret:env/EXPERIMENT_MTLS_CERTIFICATE\n      keyRef: secret:env/EXPERIMENT_MTLS_KEY\n",
                upstream.url(scenario.base_path())
            )
        }
    }
}

async fn schema_url() -> String {
    let base = std::env::var("ADAPTER_TEST_DATABASE_URL")
        .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL server");
    let serial = NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let schema = format!("adapter_experiment_{nanos}_{serial}");
    let (client, connection) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect the adapter test database");
    tokio::spawn(connection);
    client
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create an isolated experiment schema");
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    tokio_postgres::Config::from_str(&url).expect("scoped database URL parses");
    url
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind a free facade port")
        .local_addr()
        .expect("facade address")
        .port()
}

/// Assert the recorded wire exchange matches the documented fixture and
/// that the declared authentication mode, including the private assertion,
/// really reached the synthetic source.
pub fn assert_transcript(scenario: Scenario, fixture: &Fixture, upstream: &Upstream) {
    let requests = upstream.requests();
    assert_eq!(
        requests.len(),
        fixture.exchanges().len(),
        "requests={requests:#?}; TLS handshakes={:#?}",
        upstream.handshake_errors()
    );
    for (request, exchange) in requests.iter().zip(fixture.exchanges()) {
        let expected = &exchange["request"];
        assert_eq!(request.method, expected["method"], "{request:#?}");
        let is_token = expected
            .get("tokenRequest")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mut target = if is_token {
            expected["path"].as_str().expect("token path").to_owned()
        } else if scenario == Scenario::GraphQlCases {
            scenario.base_path().to_owned()
        } else {
            format!(
                "{}{}",
                scenario.base_path(),
                expected["path"].as_str().expect("data path")
            )
        };
        if let Some(query) = expected.get("query").and_then(Value::as_str) {
            target.push('?');
            target.push_str(query);
        }
        assert_eq!(request.target, target, "{request:#?}");
        if !is_token {
            match expected.get("body") {
                Some(body) if !body.is_null() => {
                    let actual: Value = serde_json::from_slice(&request.body)
                        .expect("the source request body is JSON");
                    assert_eq!(&actual, body, "{request:#?}");
                }
                _ => assert!(request.body.is_empty(), "{request:#?}"),
            }
        }
    }

    match scenario {
        Scenario::FhirPatient | Scenario::FhirConditionalCreate => {
            assert_eq!(
                requests[0].header("authorization"),
                Some(
                    format!(
                        "Basic {}",
                        STANDARD.encode(format!("{OAUTH_CLIENT_ID}:{OAUTH_CLIENT_SECRET}"))
                    )
                    .as_str()
                )
            );
            for request in &requests[1..] {
                assert_eq!(
                    request.header("authorization"),
                    Some(format!("Bearer {ACCESS_TOKEN}").as_str())
                );
            }
        }
        Scenario::GraphQlCases => {
            assert_eq!(requests[0].header("x-api-key"), Some(API_KEY));
            assert!(requests[0].header("authorization").is_none());
        }
        Scenario::RestMutualTls | Scenario::SecondProfile => {
            let form: BTreeMap<String, String> = url::form_urlencoded::parse(&requests[0].body)
                .into_owned()
                .collect();
            assert_eq!(
                form.get("client_id").map(String::as_str),
                Some(OAUTH_CLIENT_ID)
            );
            assert_eq!(
                form.get("client_assertion_type").map(String::as_str),
                Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            );
            let assertion = form.get("client_assertion").expect("signed assertion");
            let segments: Vec<&str> = assertion.split('.').collect();
            assert_eq!(segments.len(), 3, "a compact signed JWT");
            assert!(!segments[2].is_empty(), "the JWT carries a signature");
            let jwk: jsonwebtoken::jwk::Jwk =
                serde_json::from_str(ASSERTION_JWK).expect("the assertion JWK parses");
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
            validation.set_issuer(&[OAUTH_CLIENT_ID]);
            let token_endpoint = upstream.url("/oauth/token");
            validation.set_audience(&[token_endpoint.as_str()]);
            let claims = jsonwebtoken::decode::<Value>(
                assertion,
                &jsonwebtoken::DecodingKey::from_jwk(&jwk)
                    .expect("the public assertion key decodes"),
                &validation,
            )
            .expect("the private-key JWT signature and registered claims verify")
            .claims;
            assert_eq!(claims["iss"], OAUTH_CLIENT_ID);
            assert_eq!(claims["sub"], OAUTH_CLIENT_ID);
            assert_eq!(claims["aud"], token_endpoint);
            assert!(
                claims["exp"].as_u64().expect("assertion expiry")
                    > claims["iat"].as_u64().expect("assertion issued-at")
            );
            assert_eq!(
                requests[1].header("authorization"),
                Some(format!("Bearer {ACCESS_TOKEN}").as_str())
            );
        }
    }
    if scenario != Scenario::GraphQlCases {
        assert_eq!(
            fixture.exchanges()[0]["response"]["body"]["expires_in"].as_u64(),
            Some(300),
            "synthetic OAuth credentials have the declared bounded lifetime"
        );
    }
}

pub fn assert_fixture_response(fixture: &Fixture, response: &(u16, String, Value)) {
    assert_eq!(
        response.0,
        u16::try_from(
            fixture.expected()["status"]
                .as_u64()
                .expect("expected status")
        )
        .expect("status fits u16"),
        "{}",
        response.2
    );
    for (name, expected) in fixture.expected()["headers"]
        .as_object()
        .expect("expected response headers")
    {
        let actual = response
            .1
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim());
        assert_eq!(actual, expected.as_str(), "response header {name}");
    }
    if fixture.expected()["body"].get("pageStateToken").is_some() {
        let mut expected = fixture.expected()["body"].clone();
        let cursor = response.2["pageStateToken"]
            .as_str()
            .expect("the GraphQL result carries a sealed continuation");
        assert!(cursor.len() > 20, "the continuation is sealed");
        assert_ne!(cursor, "Y3Vyc29yOjUw", "the source cursor is not exposed");
        expected["pageStateToken"] = Value::String(cursor.to_owned());
        assert_eq!(response.2, expected, "closed GraphQL facade shape");
    } else {
        assert_eq!(
            response.2,
            fixture.expected()["body"],
            "closed facade shape"
        );
    }
}
