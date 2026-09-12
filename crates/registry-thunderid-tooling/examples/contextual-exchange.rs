//! Real pinned-container RFC 8693 authority-preservation proof.
//! Keys, assertions and bearer tokens stay in memory. Direct fixed-form probes
//! exercise invalid requests; no protected response body is printed.
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_authcommon::client_assertion::{
    sign_client_assertion, ClientAssertionRequest,
};
use registry_platform_crypto::{PrivateJwk, PublicJwk};
use registry_platform_httputil::{PrivateKeyJwt, PrivateKeyJwtConfig};
use registry_thunderid_tooling::{
    container::Session, description::*, local, render, version::ThunderIdPin,
};
use serde_json::{json, Value};

type Result<T> = std::result::Result<T, &'static str>;
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
const TARGET: &str = "urn:registry:gate0:target";
const OTHER: &str = "urn:registry:gate0:other";
const AUTHORITY_RESOURCE: &str = "urn:registry:gate0:authority";
const CLIENT: &str = "gate0-agent-a";
const SECOND_CLIENT: &str = "gate0-agent-b";
const AUTHORITY_ID: &str = "0197aaaa-0000-7000-8000-0000000000b3";
const BOOTSTRAP_SCOPE: &str = "grants:assert";
const TARGET_SCOPE: &str = "records:get";

fn check(condition: bool, reason: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(reason)
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}
fn random() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("randomness");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn key(kid: &str) -> (PrivateJwk, String) {
    let secret = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let point = secret.verifying_key().to_encoded_point(false);
    let public = json!({"kty":"EC","crv":"P-256","alg":"ES256","kid":kid,"use":"sig",
        "x":URL_SAFE_NO_PAD.encode(point.x().expect("x")),"y":URL_SAFE_NO_PAD.encode(point.y().expect("y"))});
    let mut private = public.clone();
    private["d"] = json!(URL_SAFE_NO_PAD.encode(secret.to_bytes()));
    (
        PrivateJwk::parse(&private.to_string()).expect("generated key"),
        json!({"keys":[public]}).to_string(),
    )
}
fn signed(key: &PrivateJwk, kid: &str, claims: &Value) -> Result<String> {
    let header = URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","typ":"JWT","kid":kid}).to_string());
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let input = format!("{header}.{payload}");
    let signature = registry_platform_crypto::sign(input.as_bytes(), key)
        .map_err(|_| "assertion signing failed")?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

struct PublicKeys {
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    port: u16,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl PublicKeys {
    fn start(a: String, b: String) -> Result<Self> {
        // Only generated public JWKS are served. Docker Desktop resolves this
        // host through host.docker.internal; no protected endpoint lives here.
        let listener =
            TcpListener::bind(("0.0.0.0", 0)).map_err(|_| "JWKS listener unavailable")?;
        let port = listener
            .local_addr()
            .map_err(|_| "JWKS address unavailable")?
            .port();
        listener
            .set_nonblocking(true)
            .map_err(|_| "JWKS listener setup failed")?;
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let running = stop.clone();
        let count = requests.clone();
        let thread = std::thread::spawn(move || {
            while !running.load(Ordering::Relaxed) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut bytes = [0u8; 4096];
                    let n = stream.read(&mut bytes).unwrap_or(0);
                    let request = String::from_utf8_lossy(&bytes[..n]);
                    let body = if request.starts_with("GET /a/jwks ") {
                        Some(&a)
                    } else if request.starts_with("GET /b/jwks ") {
                        Some(&b)
                    } else {
                        None
                    };
                    if let Some(body) = body {
                        count.fetch_add(1, Ordering::Relaxed);
                        let _=write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body);
                    } else {
                        let _=stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        });
        Ok(Self {
            stop,
            requests,
            port,
            thread: Some(thread),
        })
    }
    fn issuer(&self, which: &str) -> String {
        format!("http://host.docker.internal:{}/{which}", self.port)
    }
}
impl Drop for PublicKeys {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn resource(id: &str, identifier: &str, handle: &str, action: &str) -> ResourceServer {
    ResourceServer {
        id: id.into(),
        name: format!("Gate0 {handle} {id}"),
        identifier: identifier.into(),
        description: "Synthetic acceptance resource".into(),
        resources: vec![Resource {
            name: handle.into(),
            handle: handle.into(),
            parent: None,
            description: "Acceptance resource".into(),
            actions: vec![Action {
                name: action.into(),
                handle: action.into(),
                description: "Acceptance operation".into(),
            }],
        }],
    }
}
fn description(
    root: &Path,
    port: u16,
    id: &str,
    keys: &PublicKeys,
    client_keys: [String; 2],
) -> IssuerDescription {
    let machine_clients = client_keys
        .into_iter()
        .enumerate()
        .map(|(i, public_jwks)| MachineClient {
            agent_id: format!("0197aaaa-0000-7000-8000-0000000000a{}", i + 1),
            name: format!("Gate0 Agent {i}"),
            description: "Synthetic agent".into(),
            client_id: if i == 0 { CLIENT } else { SECOND_CLIENT }.into(),
            public_jwks,
            attributes: BTreeMap::new(),
            token_attributes: vec![],
            access_token_lifetime_seconds: 300,
            token_exchange: Some(TokenExchangeClient {
                assertion_resource_server_id: AUTHORITY_ID.into(),
                assertion_scope: BOOTSTRAP_SCOPE.into(),
            }),
        })
        .collect();
    IssuerDescription {
        session: SessionIdentity {
            label: format!("gate0-{}", &id[..12]),
            id: id.into(),
        },
        port,
        state_root: root.into(),
        organization_unit: OrganizationUnit {
            id: DEFAULT_OU_ID.into(),
            handle: DEFAULT_OU_HANDLE.into(),
            name: "Default".into(),
            description: "Default".into(),
        },
        resource_servers: vec![
            resource(
                "0197aaaa-0000-7000-8000-0000000000b1",
                TARGET,
                "records",
                "get",
            ),
            resource(
                "0197aaaa-0000-7000-8000-0000000000b2",
                OTHER,
                "records",
                "get",
            ),
            resource(AUTHORITY_ID, AUTHORITY_RESOURCE, "grants", "assert"),
        ],
        roles: vec![Role {
            id: "0197aaaa-0000-7000-8000-0000000000c1".into(),
            name: "Gate0 Bootstrap".into(),
            description: "Assertion lookup only".into(),
            permissions: vec![(AUTHORITY_ID.into(), vec![BOOTSTRAP_SCOPE.into()])],
            assigned_agents: vec![
                "0197aaaa-0000-7000-8000-0000000000a1".into(),
                "0197aaaa-0000-7000-8000-0000000000a2".into(),
            ],
        }],
        machine_clients,
        compatibility_clients: vec![],
        schema_attributes: vec![],
        exchange_issuers: ["a", "b", "unavailable"]
            .iter()
            .enumerate()
            .map(|(i, which)| ExchangeIssuer {
                id: format!("0197aaaa-0000-7000-8000-0000000000d{}", i + 1),
                name: format!("Gate0 Authority {which}"),
                issuer: keys.issuer(which),
                jwks_endpoint: format!("{}/jwks", keys.issuer(which)),
            })
            .collect(),
    }
}
struct Running {
    description: IssuerDescription,
    pin: ThunderIdPin,
}
impl Running {
    fn session(&self) -> Session<'_> {
        Session {
            label: &self.description.session.label,
            id: &self.description.session.id,
            port: self.description.port,
            state_root: &self.description.state_root,
            image: &self.pin.image,
        }
    }
    fn start(description: IssuerDescription) -> Result<Self> {
        description
            .validate()
            .map_err(|_| "Gate0 description validation failed")?;
        let pin = ThunderIdPin::load().map_err(|_| "upstream pin invalid")?;
        let this = Self { description, pin };
        let root = &this.description.state_root;
        std::fs::create_dir_all(root.join("secrets"))
            .map_err(|_| "private directory creation failed")?;
        for name in ["direct_auth_secret", "throwaway-bootstrap-password"] {
            let path = root.join("secrets").join(name);
            std::fs::write(&path, random()).map_err(|_| "secret initialization failed")?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| "secret permissions failed")?;
        }
        render::render(&this.description).map_err(|_| "native resource rendering failed")?;
        local::start(&this.session(), std::path::Path::new("docker"), &mut || {
            false
        })
        .map_err(|_| "owned issuer bootstrap/start/public JWKS checks failed")?;
        Ok(this)
    }
    fn issuer(&self) -> String {
        format!("http://127.0.0.1:{}", self.description.port)
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = local::stop(&self.session(), std::path::Path::new("docker"));
    }
}

fn http(url: &str, form: Option<&[(String, String)]>) -> Result<(u16, Value)> {
    let mut command = Command::new("curl");
    command.args([
        "--silent",
        "--max-time",
        "10",
        "--write-out",
        "\n%{http_code}",
    ]);
    if form.is_some() {
        command.args([
            "--header",
            "Content-Type: application/x-www-form-urlencoded",
            "--data-binary",
            "@-",
        ]);
    }
    command
        .arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut process = command.spawn().map_err(|_| "HTTP probe unavailable")?;
    if let Some(form) = form {
        let mut encoder = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in form {
            encoder.append_pair(k, v);
        }
        process
            .stdin
            .take()
            .ok_or("HTTP stdin unavailable")?
            .write_all(encoder.finish().as_bytes())
            .map_err(|_| "HTTP request failed")?;
    }
    let output = process
        .wait_with_output()
        .map_err(|_| "HTTP probe failed")?;
    check(output.status.success(), "HTTP transport failed")?;
    let text = String::from_utf8(output.stdout).map_err(|_| "HTTP response encoding invalid")?;
    let (body, status) = text.rsplit_once('\n').ok_or("HTTP status missing")?;
    let status = status.parse().map_err(|_| "HTTP status invalid")?;
    Ok((status, serde_json::from_str(body).unwrap_or(Value::Null)))
}
fn post(
    issuer: &str,
    key: &PrivateJwk,
    client: &str,
    subject: Option<(&str, &str)>,
    resource: &str,
    scope: &str,
) -> Result<(u16, Value)> {
    let assertion = sign_client_assertion(
        key,
        &ClientAssertionRequest {
            client_id: client,
            audience: issuer,
            lifetime_seconds: 60,
            issued_at: now() as i64,
        },
    )
    .map_err(|_| "client assertion signing failed")?;
    let mut form = vec![
        (
            "grant_type".into(),
            if subject.is_some() {
                TOKEN_EXCHANGE
            } else {
                "client_credentials"
            }
            .into(),
        ),
        ("client_id".into(), client.into()),
        (
            "client_assertion_type".into(),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
        ),
        ("client_assertion".into(), assertion.as_str().into()),
        ("resource".into(), resource.into()),
        ("scope".into(), scope.into()),
    ];
    if let Some((token, typ)) = subject {
        form.extend([
            ("subject_token".into(), token.into()),
            ("subject_token_type".into(), typ.into()),
            ("requested_token_type".into(), ACCESS.into()),
        ]);
    }
    http(&format!("{issuer}/oauth2/token"), Some(&form))
}
fn token(response: &Value) -> Result<&str> {
    response["access_token"]
        .as_str()
        .ok_or("access token missing")
}
fn verified(token: &str, jwks: &Value) -> Result<Value> {
    let parts: Vec<_> = token.split('.').collect();
    check(parts.len() == 3, "token is not a compact JWS")?;
    let decode = |s: &str| {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| "token encoding invalid")
    };
    let header: Value =
        serde_json::from_slice(&decode(parts[0])?).map_err(|_| "token header invalid")?;
    check(header["typ"] == "at+jwt", "access token type invalid")?;
    let value = jwks["keys"]
        .as_array()
        .ok_or("issuer JWKS missing")?
        .iter()
        .find(|jwk| jwk["kid"] == header["kid"])
        .ok_or("issuer signing key missing")?;
    let jwk = PublicJwk::parse(&value.to_string()).map_err(|_| "issuer key invalid")?;
    check(
        jwk.alg
            .as_deref()
            .is_none_or(|alg| Some(alg) == header["alg"].as_str()),
        "issuer algorithm mismatch",
    )?;
    registry_platform_crypto::verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &decode(parts[2])?,
        &jwk,
    )
    .map_err(|_| "issuer signature invalid")?;
    serde_json::from_slice(&decode(parts[1])?).map_err(|_| "token claims invalid")
}
fn grant(issuer: &str, source: &str) -> Value {
    let time = now();
    json!({"iss":source,"aud":issuer,"sub":"unregistered-task-agent-subject","iat":time,"exp":time+60,"jti":random(),
    "scope":TARGET_SCOPE,"registry_actor_kind":"agent","registry_grant_id":"g-synthetic-1","registry_grant_authority":"authority-a",
    "registry_grant_client":CLIENT,"registry_grant_resource":TARGET,"registry_purpose":"synthetic-check","registry_grant_exp":time+900,
    "registry_grant_bounds":{"type":"evidence","requirement":"synthetic-requirement"},
    "identity":{"demographics-v1":{"full_name":"Synthetic Canary","birth_date":"1998-04-02"}},"registry_approver":"h:synthetic-approver"})
}
fn bounds(claims: &Value, client: &str, resource: &str, source: &str, time: u64) -> bool {
    claims["client_id"] == client
        && claims["registry_grant_client"] == client
        && claims["registry_grant_resource"] == resource
        && claims["registry_grant_source_issuer"] == source
        && claims["registry_grant_authority"] == "authority-a"
        && claims["registry_grant_exp"]
            .as_u64()
            .is_some_and(|exp| time < exp)
        && claims["exp"].as_u64().is_some_and(|exp| time < exp)
        && claims["registry_grant_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
}
fn exchanged(
    issuer: &str,
    key: &PrivateJwk,
    client: &str,
    subject: &str,
    resource: &str,
    scope: &str,
    jwks: &Value,
) -> Result<(String, Value)> {
    let (status, response) = post(issuer, key, client, Some((subject, JWT)), resource, scope)?;
    check(status == 200, "exchange rejected")?;
    check(
        response["issued_token_type"] == ACCESS,
        "issued token type missing or incorrect",
    )?;
    check(
        response.get("refresh_token").is_none(),
        "unexpected refresh token",
    )?;
    let compact = token(&response)?.to_owned();
    let claims = verified(&compact, jwks)?;
    Ok((compact, claims))
}
fn run(root: &Path) -> Result<()> {
    std::fs::create_dir(root)
        .map_err(|_| "state must be a fresh directory; existing state is never removed")?;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| "state permissions failed")?;
    let (client_key, client_jwks) = key("client-a");
    let (second_key, second_jwks) = key("client-b");
    let (authority_key, authority_jwks) = key("authority-a");
    let (other_key, other_jwks) = key("authority-b");
    let keys = PublicKeys::start(authority_jwks, other_jwks)?;
    let socket = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "issuer port unavailable")?;
    let port = socket
        .local_addr()
        .map_err(|_| "issuer port unavailable")?
        .port();
    drop(socket);
    let started = Instant::now();
    let live = Running::start(description(
        root,
        port,
        &random(),
        &keys,
        [client_jwks, second_jwks],
    ))?;
    let issuer = live.issuer();
    let discovery = loop {
        if let Ok((200, body)) = http(&format!("{issuer}/.well-known/openid-configuration"), None) {
            break body;
        }
        if started.elapsed() > Duration::from_secs(120) {
            return Err("issuer readiness deadline exceeded");
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    check(discovery["issuer"] == issuer, "discovery issuer mismatch")?;
    let uri = discovery["jwks_uri"]
        .as_str()
        .ok_or("JWKS discovery missing")?;
    check(
        uri.starts_with(&format!("{issuer}/")),
        "unexpected JWKS origin",
    )?;
    let (status, jwks) = http(uri, None)?;
    check(status == 200, "issuer JWKS unavailable")?;
    println!(
        "PASS Gate0.readiness ({} ms)",
        started.elapsed().as_millis()
    );
    let original = grant(&issuer, &keys.issuer("a"));
    let assertion = signed(&authority_key, "authority-a", &original)?;
    let (access, claims) = exchanged(
        &issuer,
        &client_key,
        CLIENT,
        &assertion,
        TARGET,
        TARGET_SCOPE,
        &jwks,
    )?;
    for name in GRANT_ATTRIBUTES
        .iter()
        .copied()
        .filter(|name| *name != "registry_grant_source_issuer")
    {
        check(
            claims[name] == original[name],
            "grant attribute changed or dropped",
        )?;
    }
    check(
        claims["sub"] == original["sub"],
        "unregistered assertion subject changed",
    )?;
    check(claims["iss"] == issuer, "access issuer mismatch")?;
    check(claims["scope"] == TARGET_SCOPE, "scope changed")?;
    check(
        claims["exp"]
            .as_u64()
            .zip(claims["iat"].as_u64())
            .is_some_and(|(exp, iat)| exp - iat == 300),
        "access lifetime differs from configured 300 seconds",
    )?;
    check(
        bounds(&claims, CLIENT, TARGET, &keys.issuer("a"), now()),
        "correct bound token refused by expected consumer comparisons",
    )?;
    println!("PASS Gate0.jwt-nested-claims-and-unknown-subject");
    let provider = PrivateKeyJwt::new(
        PrivateKeyJwtConfig::new(
            format!("{issuer}/oauth2/token")
                .parse()
                .map_err(|_| "token endpoint invalid")?,
            CLIENT,
            client_key.clone(),
        )
        .with_audience(issuer.clone())
        .with_resource(TARGET)
        .with_scopes([TARGET_SCOPE]),
    )
    .map_err(|_| "shared provider configuration refused")?;
    let runtime =
        tokio::runtime::Runtime::new().map_err(|_| "shared provider runtime unavailable")?;
    let provided = runtime
        .block_on(provider.exchange(&assertion))
        .map_err(|_| "shared provider exchange refused")?;
    let header = provided.authorization_header_value();
    let compact = header
        .to_str()
        .map_err(|_| "shared provider token encoding invalid")?
        .strip_prefix("Bearer ")
        .ok_or("shared provider bearer prefix missing")?;
    let provided_claims = verified(compact, &jwks)?;
    check(
        bounds(&provided_claims, CLIENT, TARGET, &keys.issuer("a"), now()),
        "shared provider lost grant bounds",
    )?;
    println!("PASS Gate0.shared-private-key-jwt-provider");

    let mut breg = original.clone();
    breg["registry_grant_bounds"] = json!({"type":"breg","permissions":[{"collection":"synthetic_records","operations":["get","list","submit_request"]}]});
    let breg_assertion = signed(&authority_key, "authority-a", &breg)?;
    let (_, breg_claims) = exchanged(
        &issuer,
        &client_key,
        CLIENT,
        &breg_assertion,
        TARGET,
        TARGET_SCOPE,
        &jwks,
    )?;
    check(
        breg_claims["registry_grant_bounds"] == breg["registry_grant_bounds"],
        "nested BREG permissions dropped",
    )?;
    println!("PASS Gate0.breg-permission-bounds");
    let mut spoofed = original.clone();
    spoofed["iss"] = json!(keys.issuer("b"));
    spoofed["registry_grant_source_issuer"] = json!(keys.issuer("a"));
    let forged = signed(&other_key, "authority-b", &spoofed)?;
    let (_, other_claims) = exchanged(
        &issuer,
        &client_key,
        CLIENT,
        &forged,
        TARGET,
        TARGET_SCOPE,
        &jwks,
    )?;
    check(
        other_claims["registry_grant_source_issuer"] == keys.issuer("b"),
        "external issuer provenance spoof survived mapping",
    )?;
    check(
        !bounds(&other_claims, CLIENT, TARGET, &keys.issuer("a"), now()),
        "another issuer acquired authority A",
    )?;
    let wrong_key = signed(&other_key, "authority-b", &original)?;
    check(
        post(
            &issuer,
            &client_key,
            CLIENT,
            Some((&wrong_key, JWT)),
            TARGET,
            TARGET_SCOPE,
        )?
        .0 != 200,
        "wrong authority signing key accepted",
    )?;
    println!("PASS Gate0.provenance-and-issuer-confusion");
    for source in [keys.issuer("unregistered"), keys.issuer("unavailable")] {
        let mut input = original.clone();
        input["iss"] = json!(source);
        let input = signed(&authority_key, "authority-a", &input)?;
        check(
            post(
                &issuer,
                &client_key,
                CLIENT,
                Some((&input, JWT)),
                TARGET,
                TARGET_SCOPE,
            )?
            .0 != 200,
            "unknown or unavailable authority accepted",
        )?;
    }
    let mut missing = original.clone();
    missing
        .as_object_mut()
        .ok_or("grant fixture malformed")?
        .remove("registry_grant_id");
    let missing = signed(&authority_key, "authority-a", &missing)?;
    let (_, missing_claims) = exchanged(
        &issuer,
        &client_key,
        CLIENT,
        &missing,
        TARGET,
        TARGET_SCOPE,
        &jwks,
    )?;
    check(
        missing_claims.get("registry_grant_id").is_none()
            && !bounds(&missing_claims, CLIENT, TARGET, &keys.issuer("a"), now()),
        "missing grant ID was manufactured during exchange",
    )?;
    println!("PASS Gate0.unregistered-unavailable-and-missing-grant");

    let (_, cross_client) = exchanged(
        &issuer,
        &second_key,
        SECOND_CLIENT,
        &assertion,
        TARGET,
        TARGET_SCOPE,
        &jwks,
    )?;
    check(
        cross_client["registry_grant_client"] == CLIENT,
        "original grant client overwritten",
    )?;
    check(
        !bounds(
            &cross_client,
            SECOND_CLIENT,
            TARGET,
            &keys.issuer("a"),
            now(),
        ),
        "retargeted client escaped immutable bound",
    )?;
    let (_, cross_resource) = exchanged(
        &issuer,
        &client_key,
        CLIENT,
        &assertion,
        OTHER,
        TARGET_SCOPE,
        &jwks,
    )?;
    check(
        cross_resource["registry_grant_resource"] == TARGET,
        "original grant resource overwritten",
    )?;
    check(
        !bounds(&cross_resource, CLIENT, OTHER, &keys.issuer("a"), now()),
        "retargeted resource escaped immutable bound",
    )?;
    println!(
        "PASS Gate0.cross-client-and-resource-preserve-bounds (consumer enforcement required)"
    );
    let (_, renewed) = exchanged(
        &issuer,
        &client_key,
        CLIENT,
        &access,
        TARGET,
        TARGET_SCOPE,
        &jwks,
    )?;
    check(
        renewed["registry_grant_source_issuer"] == claims["registry_grant_source_issuer"]
            && renewed["registry_grant_exp"] == claims["registry_grant_exp"],
        "re-exchange changed original provenance or deadline",
    )?;
    let mut short = original.clone();
    short["registry_grant_exp"] = json!(now() + 2);
    let short_assertion = signed(&authority_key, "authority-a", &short)?;
    let (short_access, _) = exchanged(
        &issuer,
        &client_key,
        CLIENT,
        &short_assertion,
        TARGET,
        TARGET_SCOPE,
        &jwks,
    )?;
    std::thread::sleep(Duration::from_secs(3));
    let (_, past_deadline) = exchanged(
        &issuer,
        &client_key,
        CLIENT,
        &short_access,
        TARGET,
        TARGET_SCOPE,
        &jwks,
    )?;
    check(
        past_deadline["registry_grant_exp"] == short["registry_grant_exp"]
            && !bounds(&past_deadline, CLIENT, TARGET, &keys.issuer("a"), now()),
        "re-exchange extended usable authority deadline",
    )?;
    println!(
        "PASS Gate0.immutable-deadline-through-reexchange (consumer expiry enforcement required)"
    );
    let (status, bootstrap) = post(
        &issuer,
        &client_key,
        CLIENT,
        None,
        AUTHORITY_RESOURCE,
        BOOTSTRAP_SCOPE,
    )?;
    check(status == 200, "bootstrap client credentials refused")?;
    let bootstrap_claims = verified(token(&bootstrap)?, &jwks)?;
    check(
        bootstrap_claims["scope"] == BOOTSTRAP_SCOPE
            && GRANT_ATTRIBUTES
                .iter()
                .all(|name| bootstrap_claims.get(*name).is_none()),
        "bootstrap token carried grant authority",
    )?;
    let (_, bootstrap_exchange) = exchanged(
        &issuer,
        &client_key,
        CLIENT,
        token(&bootstrap)?,
        AUTHORITY_RESOURCE,
        BOOTSTRAP_SCOPE,
        &jwks,
    )?;
    check(
        GRANT_ATTRIBUTES
            .iter()
            .all(|name| bootstrap_exchange.get(*name).is_none()),
        "bootstrap re-exchange manufactured authority",
    )?;
    let (status, target_bootstrap) =
        post(&issuer, &client_key, CLIENT, None, TARGET, TARGET_SCOPE)?;
    if status == 200 {
        let c = verified(token(&target_bootstrap)?, &jwks)?;
        check(
            c["scope"] != TARGET_SCOPE && !bounds(&c, CLIENT, TARGET, &keys.issuer("a"), now()),
            "client credentials acquired target authority",
        )?;
    }
    println!("PASS Gate0.bootstrap-and-reexchange-have-no-grants");
    let (_, narrowed) = exchanged(
        &issuer,
        &client_key,
        CLIENT,
        &assertion,
        TARGET,
        "records:get records:patch",
        &jwks,
    )?;
    check(
        narrowed["scope"] == TARGET_SCOPE,
        "exchange widened requested scope",
    )?;
    check(
        post(
            &issuer,
            &client_key,
            CLIENT,
            Some((&assertion, ACCESS)),
            TARGET,
            TARGET_SCOPE,
        )?
        .0 != 200,
        "JWT assertion accepted as at+jwt access token",
    )?;
    let mut expired = original.clone();
    expired["exp"] = json!(now() - 120);
    expired["iat"] = json!(now() - 180);
    let expired = signed(&authority_key, "authority-a", &expired)?;
    check(
        post(
            &issuer,
            &client_key,
            CLIENT,
            Some((&expired, JWT)),
            TARGET,
            TARGET_SCOPE,
        )?
        .0 != 200,
        "expired assertion accepted",
    )?;
    let mut wrong_audience = original.clone();
    wrong_audience["aud"] = json!("urn:wrong-audience");
    let wrong_audience = signed(&authority_key, "authority-a", &wrong_audience)?;
    check(
        post(
            &issuer,
            &client_key,
            CLIENT,
            Some((&wrong_audience, JWT)),
            TARGET,
            TARGET_SCOPE,
        )?
        .0 != 200,
        "wrong assertion audience accepted",
    )?;
    check(
        keys.requests.load(Ordering::Relaxed) >= 2,
        "container did not fetch both authority JWKS over host networking",
    )?;
    println!("PASS Gate0.scopes-token-types-expiry-audience-and-host-jwks");
    println!("PASS Gate0.complete (pinned issuer; resource-server tests remain separate)");
    Ok(())
}
fn main() {
    let mut args = std::env::args().skip(1);
    let root = match (args.next().as_deref(), args.next()) {
        (Some("--state"), Some(root)) => PathBuf::from(root),
        _ => {
            eprintln!("usage: contextual-exchange --state FRESH_ABSOLUTE_DIRECTORY");
            std::process::exit(2);
        }
    };
    if args.next().is_some() {
        eprintln!("unexpected arguments");
        std::process::exit(2);
    }
    if !root.is_absolute() {
        eprintln!("state must be absolute");
        std::process::exit(2);
    }
    if let Err(reason) = run(&root) {
        eprintln!("FAIL Gate0: {reason}");
        std::process::exit(1);
    }
}
