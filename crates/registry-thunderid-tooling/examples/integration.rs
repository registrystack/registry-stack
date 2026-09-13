//! Real-container integration driver for the P3 acceptance subcases.
//!
//! Invoked by `products/identity/scripts/test-thunderid-integration.py` as a
//! built test binary (`--case A09.schema-and-restart` and friends). It drives
//! one owned ThunderID session through the tooling crate and performs token
//! exchanges with the shared platform client — it implements no OAuth client
//! of its own. It creates and cleans up only its own synthetic resources,
//! publishes only on numeric loopback, and never prints a secret, key,
//! assertion, or token.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_platform_crypto::PrivateJwk;
use registry_platform_httputil::{PrivateKeyJwt, PrivateKeyJwtConfig, TokenProvider};
use registry_thunderid_tooling::bootstrap::{Bootstrap, SystemCommandRunner};
use registry_thunderid_tooling::container::Session;
use registry_thunderid_tooling::description::{
    ClientSecretMethod, CompatibilityClient, IssuerDescription, MachineClient, OrganizationUnit,
    Resource, ResourceServer, Role, SessionIdentity,
};
use registry_thunderid_tooling::render;
use registry_thunderid_tooling::version::ThunderIdPin;

const PORT: u16 = 18_493;
const RESOURCE: &str = "urn:registry:tooling-test:evidence";
const CLIENT_ID: &str = "synthetic-machine-client";
const AGENT_ID: &str = "0197aaaa-0000-7000-8000-0000000000a1";
const COMPAT_AGENT_ID: &str = "0197aaaa-0000-7000-8000-0000000000a2";
const SERVER_ID: &str = "0197aaaa-0000-7000-8000-0000000000b1";
const ROLE_ID: &str = "0197aaaa-0000-7000-8000-0000000000c1";

fn fail(message: &str) -> ! {
    eprintln!("FAIL: {message}");
    std::process::exit(1);
}

/// A fresh ES256 client keypair, generated at run time so no key material
/// ever lives in the tree. The private half stays in owner-only files under
/// the session state; only the public JWKS is rendered into the
/// registration.
fn fresh_client_key(kid: &str) -> (PrivateJwk, String) {
    let secret = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let point = secret.verifying_key().to_encoded_point(false);
    let encode = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
    let public_jwks = format!(
        "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"kid\":\"{kid}\",\"use\":\"sig\",\"key_ops\":[\"verify\"],\"x\":\"{}\",\"y\":\"{}\"}}]}}",
        encode(point.x().expect("x")),
        encode(point.y().expect("y"))
    );
    let jwk = serde_json::json!({
        "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": kid,
        "x": encode(point.x().expect("x")),
        "y": encode(point.y().expect("y")),
        "d": encode(&secret.to_bytes()),
    });
    let private = PrivateJwk::parse(&jwk.to_string()).expect("the generated key parses");
    (private, public_jwks)
}

fn description(state_root: &Path, public_jwks: String) -> IssuerDescription {
    let mut attributes = std::collections::BTreeMap::new();
    attributes.insert(
        "synthetic_tag".to_owned(),
        serde_json::Value::String("fixture-agency".to_owned()),
    );
    attributes.insert(
        "evidence_tags".to_owned(),
        serde_json::json!(["policy-a", "policy-b"]),
    );
    IssuerDescription {
        session: SessionIdentity {
            label: "identity-integration".to_owned(),
            id: "b2c3d4e5f6071829".to_owned(),
        },
        port: PORT,
        state_root: state_root.to_path_buf(),
        organization_unit: OrganizationUnit {
            id: registry_thunderid_tooling::description::DEFAULT_OU_ID.to_owned(),
            handle: registry_thunderid_tooling::description::DEFAULT_OU_HANDLE.to_owned(),
            name: "Default".to_owned(),
            description: "Default organization unit".to_owned(),
        },
        resource_servers: vec![ResourceServer {
            id: SERVER_ID.to_owned(),
            name: "Synthetic Evidence".to_owned(),
            identifier: RESOURCE.to_owned(),
            description: "Synthetic resource server for the integration driver".to_owned(),
            resources: vec![Resource {
                name: "Evidence".to_owned(),
                handle: "evidence".to_owned(),
                parent: None,
                description: "Synthetic evidence operations".to_owned(),
                actions: vec![registry_thunderid_tooling::description::Action {
                    name: "Invoke".to_owned(),
                    handle: "invoke".to_owned(),
                    description: "Invoke an evidence request".to_owned(),
                }],
            }],
        }],
        roles: vec![Role {
            id: ROLE_ID.to_owned(),
            name: "Synthetic Invoker".to_owned(),
            description: "May invoke the synthetic resource".to_owned(),
            permissions: vec![(SERVER_ID.to_owned(), vec!["evidence:invoke".to_owned()])],
            assigned_agents: vec![AGENT_ID.to_owned()],
        }],
        machine_clients: vec![MachineClient {
            agent_id: AGENT_ID.to_owned(),
            name: "Synthetic Machine Client".to_owned(),
            description: "Driver private_key_jwt client".to_owned(),
            client_id: CLIENT_ID.to_owned(),
            public_jwks,
            attributes,
            token_attributes: vec!["synthetic_tag".to_owned(), "evidence_tags".to_owned()],
            access_token_lifetime_seconds: 300,
            token_exchange: None,
        }],
        compatibility_clients: vec![CompatibilityClient {
            agent_id: COMPAT_AGENT_ID.to_owned(),
            name: "Synthetic Compatibility Client".to_owned(),
            description: "Driver client_secret_post client".to_owned(),
            client_id: "synthetic-compatibility-client".to_owned(),
            method: ClientSecretMethod::Post,
            secret_file: "secrets/compatibility-client-secret".into(),
        }],
        exchange_issuers: vec![],
        schema_attributes: vec!["evidence_tags".to_owned(), "synthetic_tag".to_owned()],
    }
}

fn write_secret(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("the secrets directory exists");
    }
    std::fs::write(path, bytes).expect("the secret file is writable");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("the secret file is owner-only");
}

fn random_urlsafe(bytes: usize) -> String {
    let mut buffer = vec![0_u8; bytes];
    getrandom::fill(&mut buffer).expect("the host supplies randomness");
    URL_SAFE_NO_PAD.encode(buffer)
}

struct Live {
    issuer: String,
}

/// Bring a session up from nothing: setup, render, bootstrap, start, and
/// wait for discovery. Every step's failure names itself.
fn bring_up(state_root: &Path, public_jwks: String) -> Live {
    let pin = ThunderIdPin::load().expect("the maintained pin loads");
    let description = description(state_root, public_jwks);
    description
        .validate()
        .expect("the driver description validates");
    let session = Session {
        label: &description.session.label,
        id: &description.session.id,
        port: description.port,
        state_root: &description.state_root,
        image: &pin.image,
    };
    std::fs::create_dir_all(state_root.join("secrets")).expect("the state root exists");
    write_secret(
        &state_root.join("secrets/compatibility-client-secret"),
        random_urlsafe(32).as_bytes(),
    );
    write_secret(
        &state_root.join("secrets/admin-password"),
        random_urlsafe(24).as_bytes(),
    );
    write_secret(
        &state_root.join("secrets/direct_auth_secret"),
        random_urlsafe(24).as_bytes(),
    );
    write_secret(
        &state_root.join("secrets/throwaway-bootstrap-password"),
        random_urlsafe(24).as_bytes(),
    );

    let mut runner = SystemCommandRunner;
    session.prepare(&mut runner).unwrap_or_else(|error| {
        fail(&format!("one-time setup did not complete: {error}"));
    });
    let rendered = render::render(&description)
        .unwrap_or_else(|error| fail(&format!("rendering refused the description: {error}")));
    let mut bootstrap = Bootstrap {
        runner: &mut runner,
        image: &pin.image,
    };
    bootstrap
        .apply_agent_schema(
            &rendered.bootstrap_dir,
            &state_root.join("secrets/throwaway-bootstrap-password"),
            &[
                (
                    state_root.join("database"),
                    "/opt/thunderid/database".into(),
                ),
                (
                    state_root.join("certs"),
                    "/opt/thunderid/config/certs".into(),
                ),
                (
                    state_root.join("secrets"),
                    "/opt/thunderid/config/secrets".into(),
                ),
                (
                    state_root.join("deployment.yaml"),
                    "/opt/thunderid/deployment.yaml".into(),
                ),
                (
                    rendered.bootstrap_dir.clone(),
                    registry_thunderid_tooling::bootstrap::SCHEMA_MOUNT_POINT.into(),
                ),
            ],
        )
        .unwrap_or_else(|error| fail(&format!("the bootstrap one-shot failed: {error}")));
    session.start(&mut runner).unwrap_or_else(|error| {
        fail(&format!(
            "the serving container did not start (an unrelated port occupant is never touched): {error}"
        ));
    });
    wait_for_discovery(PORT);
    Live {
        issuer: format!("http://127.0.0.1:{PORT}"),
    }
}

fn stop(state_root: &Path) {
    let pin = ThunderIdPin::load().expect("the maintained pin loads");
    let session = Session {
        label: "identity-integration",
        id: "b2c3d4e5f6071829",
        port: PORT,
        state_root,
        image: &pin.image,
    };
    let mut runner = SystemCommandRunner;
    session
        .stop(&mut runner)
        .expect("the owned container stops");
}

fn restart(state_root: &Path) {
    stop(state_root);
    let pin = ThunderIdPin::load().expect("the maintained pin loads");
    let session = Session {
        label: "identity-integration",
        id: "b2c3d4e5f6071829",
        port: PORT,
        state_root,
        image: &pin.image,
    };
    let mut runner = SystemCommandRunner;
    session
        .start(&mut runner)
        .expect("the session restarts on retained state");
    wait_for_discovery(PORT);
}

fn wait_for_discovery(port: u16) {
    let issuer = format!("http://127.0.0.1:{port}");
    for _ in 0..60 {
        if let Ok(response) = ureq_well_known(&issuer) {
            if response {
                return;
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    fail("the issuer did not answer discovery within the bounded wait");
}

/// One bounded GET of the discovery document's status. This check is
/// reachability only; the functional check is the token exchange.
fn ureq_well_known(issuer: &str) -> Result<bool, ()> {
    let output = std::process::Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "5",
            &format!("{issuer}/.well-known/openid-configuration"),
        ])
        .output()
        .map_err(|_| ())?;
    let status = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Ok(status == "200")
}

/// The functional readiness check: the configured client obtains a correctly
/// scoped token through the shared platform provider.
fn exchange(issuer: &str, key: &PrivateJwk) -> Result<serde_json::Value, String> {
    let endpoint: url::Url = format!("{issuer}/oauth2/token")
        .parse()
        .expect("the token endpoint parses");
    let provider = PrivateKeyJwt::new(
        PrivateKeyJwtConfig::new(endpoint, CLIENT_ID, key.clone())
            .with_audience(issuer.to_owned())
            .with_resource(RESOURCE)
            .with_scopes(["evidence:invoke"]),
    )
    .map_err(|error| format!("the provider refused its configuration: {error}"))?;
    let token = tokio_block_on(provider.bearer_token())
        .map_err(|error| format!("the token exchange failed: {error}"))?;
    // The public header accessor is the one sanctioned way to read the
    // credential: strip the scheme and decode locally, never logging it.
    let header = token.authorization_header_value();
    let header = header
        .to_str()
        .map_err(|_| "the credential is not header-safe ASCII".to_owned())?;
    decode_token_claims(header.strip_prefix("Bearer ").unwrap_or(header))
}

fn tokio_block_on<F: std::future::Future>(future: F) -> F::Output {
    // A tiny current-thread runtime: one exchange at a time is all this
    // driver ever needs.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime is available")
        .block_on(future)
}

fn decode_token_claims(compact: &str) -> Result<serde_json::Value, String> {
    let payload = compact
        .split('.')
        .nth(1)
        .ok_or("the credential is not a compact JWT")?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| "the credential payload is not base64url")?;
    serde_json::from_slice(&decoded).map_err(|_| "the credential payload is not JSON".to_owned())
}

fn require(condition: bool, message: &str) {
    if !condition {
        fail(message);
    }
}

fn state_dir(base: &Path) -> PathBuf {
    base.join("session-state")
}

/// Remove this session's own container by its exact name before a case
/// recreates the state. The name encodes this driver's label and session id,
/// so nothing unrelated is ever touched; an absent container is not an error.
fn pre_clean() {
    let _ = std::process::Command::new("docker")
        .args(["rm", "-f", "thunderid-identity-integration-b2c3d4e5f607"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    std::thread::sleep(Duration::from_secs(6));
}

fn main() {
    let mut case = None;
    let mut state = PathBuf::from("/tmp/registry-thunderid-integration");
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--case" => case = arguments.next(),
            "--state" => state = PathBuf::from(arguments.next().expect("--state takes a value")),
            other => fail(&format!("unknown argument {other}")),
        }
    }
    let case = case.unwrap_or_else(|| fail("--case is required"));
    std::fs::create_dir_all(&state).expect("the state base is writable");
    let state_root = state_dir(&state);

    match case.as_str() {
        "A09.schema-and-restart" => {
            pre_clean();
            let _ = std::fs::remove_dir_all(&state_root);
            let (key, public_jwks) = fresh_client_key("integration-key-1");
            let live = bring_up(&state_root, public_jwks);
            let claims = exchange(&live.issuer, &key)
                .unwrap_or_else(|error| fail(&format!("the first exchange failed: {error}")));
            require(
                claims.get("aud").and_then(serde_json::Value::as_str) == Some(RESOURCE),
                "the token audience is not the resource identifier",
            );
            require(
                claims
                    .get("synthetic_tag")
                    .and_then(serde_json::Value::as_str)
                    == Some("fixture-agency"),
                "the static agent attribute is not emitted",
            );
            require(
                claims.get("evidence_tags") == Some(&serde_json::json!(["policy-a", "policy-b"])),
                "the static requester-tag array is not emitted intact",
            );
            require(
                claims.get("scope").and_then(serde_json::Value::as_str) == Some("evidence:invoke"),
                "the token scope is not the granted permission",
            );
            // Restart with retained state: identity, registration, and data
            // all survive; no re-bootstrap happens (the marker persists).
            let marker = std::fs::read_to_string(state_root.join("session.json"))
                .expect("the session state is retained");
            restart(&state_root);
            let after = std::fs::read_to_string(state_root.join("session.json"))
                .expect("the session state is retained after restart");
            require(
                marker == after,
                "an ordinary restart rewrote the session state",
            );
            let claims = exchange(&live.issuer, &key).unwrap_or_else(|error| {
                fail(&format!("the post-restart exchange failed: {error}"))
            });
            require(
                claims
                    .get("synthetic_tag")
                    .and_then(serde_json::Value::as_str)
                    == Some("fixture-agency"),
                "the machine attributes were lost across the restart",
            );
            require(
                claims.get("evidence_tags") == Some(&serde_json::json!(["policy-a", "policy-b"])),
                "the requester-tag array was lost across the restart",
            );
            stop(&state_root);
            println!("PASS A09.schema-and-restart");
        }
        "A10.client-key-rotation" => {
            pre_clean();
            let _ = std::fs::remove_dir_all(&state_root);
            let (old_key, old_public) = fresh_client_key("integration-key-1");
            let (new_key, new_public) = fresh_client_key("integration-key-2");
            let live = bring_up(&state_root, old_public.clone());
            exchange(&live.issuer, &old_key).unwrap_or_else(|error| {
                fail(&format!("the old key stopped working too early: {error}"))
            });
            // Rotate: register both keys during the overlap, restart, prove
            // the new key works, then remove the old key and prove it no
            // longer authenticates.
            let combined = format!(
                "{{\"keys\":[{},{}]}}",
                old_public
                    .trim_start_matches("{\"keys\":[")
                    .trim_end_matches("]}"),
                new_public
                    .trim_start_matches("{\"keys\":[")
                    .trim_end_matches("]}"),
            );
            stop(&state_root);
            rewrite_agent_jwks(&state_root, &combined);
            restart(&state_root);
            exchange(&live.issuer, &new_key).unwrap_or_else(|error| {
                fail(&format!(
                    "the replacement key was refused during overlap: {error}"
                ))
            });
            exchange(&live.issuer, &old_key).unwrap_or_else(|error| {
                fail(&format!("the old key was dropped before removal: {error}"))
            });
            stop(&state_root);
            rewrite_agent_jwks(&state_root, &new_public);
            restart(&state_root);
            exchange(&live.issuer, &new_key).unwrap_or_else(|error| {
                fail(&format!(
                    "the replacement key stopped working after rotation: {error}"
                ))
            });
            require(
                exchange(&live.issuer, &old_key).is_err(),
                "the removed key still authenticates the client",
            );
            stop(&state_root);
            println!("PASS A10.client-key-rotation");
        }
        "A10.client-and-role-revocation" => {
            pre_clean();
            let _ = std::fs::remove_dir_all(&state_root);
            let (key, public_jwks) = fresh_client_key("integration-key-1");
            let live = bring_up(&state_root, public_jwks);
            exchange(&live.issuer, &key).unwrap_or_else(|error| {
                fail(&format!("the pre-revocation exchange failed: {error}"))
            });
            // Revoke the role assignment: the permission gate the resource
            // server holds must see no scope afterwards.
            stop(&state_root);
            remove_role_assignment(&state_root);
            restart(&state_root);
            if let Ok(claims) = exchange(&live.issuer, &key) {
                require(
                    claims.get("scope").and_then(serde_json::Value::as_str)
                        != Some("evidence:invoke"),
                    "the revoked permission is still granted in new tokens",
                );
            }
            stop(&state_root);
            println!("PASS A10.client-and-role-revocation");
        }
        "A15.restart-replay" => {
            pre_clean();
            let _ = std::fs::remove_dir_all(&state_root);
            let (key, public_jwks) = fresh_client_key("integration-key-1");
            let live = bring_up(&state_root, public_jwks);
            // One consumed assertion, then an issuer restart on retained
            // state, then the same assertion again: the replay store is
            // persistent, so the replay must still be refused.
            let endpoint: url::Url = format!("{}/oauth2/token", live.issuer)
                .parse()
                .expect("the token endpoint parses");
            let assertion = sign_assertion(&key, CLIENT_ID, &live.issuer);
            let first = post_assertion(&endpoint, &assertion);
            require(first, "the fresh assertion was refused");
            restart(&state_root);
            let replay = post_assertion(&endpoint, &assertion);
            require(
                !replay,
                "a consumed assertion was accepted after the issuer restart",
            );
            let fresh = post_assertion(&endpoint, &sign_assertion(&key, CLIENT_ID, &live.issuer));
            require(fresh, "a fresh assertion was refused after the restart");
            stop(&state_root);
            println!("PASS A15.restart-replay");
        }
        other => fail(&format!("unknown case {other}")),
    }
}

/// Re-register the machine client under a new JWKS by editing the rendered
/// bootstrap document and re-running the one-shot. This is the
/// state-preserving upsert path, never a database reset.
fn rewrite_agent_jwks(state_root: &Path, public_jwks: &str) {
    let path = state_root
        .join(registry_thunderid_tooling::render::BOOTSTRAP_DIR)
        .join("agents")
        .join(format!("{AGENT_ID}.yaml"));
    let text = std::fs::read_to_string(&path).expect("the agent document is readable");
    let mut document: serde_json::Value =
        serde_norway::from_str(&text).expect("the agent document parses");
    document["inboundAuthConfig"][0]["config"]["certificate"]["value"] =
        serde_json::Value::String(public_jwks.to_owned());
    std::fs::write(
        &path,
        serde_norway::to_string(&document).expect("the document serializes"),
    )
    .expect("the agent document is writable");
    rerun_bootstrap(state_root);
}

fn remove_role_assignment(state_root: &Path) {
    let path = state_root
        .join(registry_thunderid_tooling::render::RESOURCES_DIR)
        .join("roles")
        .join(format!("{ROLE_ID}.yaml"));
    let text = std::fs::read_to_string(&path).expect("the role document is readable");
    let mut document: serde_json::Value =
        serde_norway::from_str(&text).expect("the role document parses");
    document["assignments"] = serde_json::json!([]);
    std::fs::write(
        &path,
        serde_norway::to_string(&document).expect("the document serializes"),
    )
    .expect("the role document is writable");
}

fn rerun_bootstrap(state_root: &Path) {
    let pin = ThunderIdPin::load().expect("the maintained pin loads");
    let mut runner = SystemCommandRunner;
    let mut bootstrap = Bootstrap {
        runner: &mut runner,
        image: &pin.image,
    };
    bootstrap
        .apply_agent_schema(
            &state_root.join(registry_thunderid_tooling::render::BOOTSTRAP_DIR),
            &state_root.join("secrets/throwaway-bootstrap-password"),
            &[
                (
                    state_root.join("database"),
                    "/opt/thunderid/database".into(),
                ),
                (
                    state_root.join("certs"),
                    "/opt/thunderid/config/certs".into(),
                ),
                (
                    state_root.join("secrets"),
                    "/opt/thunderid/config/secrets".into(),
                ),
                (
                    state_root.join("deployment.yaml"),
                    "/opt/thunderid/deployment.yaml".into(),
                ),
                (
                    state_root.join(registry_thunderid_tooling::render::BOOTSTRAP_DIR),
                    registry_thunderid_tooling::bootstrap::SCHEMA_MOUNT_POINT.into(),
                ),
            ],
        )
        .expect("the rotation bootstrap one-shot succeeds");
}

/// Sign one 60-second client assertion with the shared assertion builder.
fn sign_assertion(key: &PrivateJwk, client_id: &str, issuer: &str) -> String {
    use registry_platform_authcommon::client_assertion::{
        sign_client_assertion, ClientAssertionRequest,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the host clock is after the epoch")
        .as_secs() as i64;
    sign_client_assertion(
        key,
        &ClientAssertionRequest {
            client_id,
            audience: issuer,
            lifetime_seconds: 60,
            issued_at: now,
        },
    )
    .expect("the assertion signs")
    .as_str()
    .to_owned()
}

/// Post one assertion directly: the A15 replay check needs to resend the
/// identical assertion, which the caching provider will not do.
fn post_assertion(endpoint: &url::Url, assertion: &str) -> bool {
    use std::io::Write;
    use std::process::Stdio;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "client_credentials")
        .append_pair("client_id", CLIENT_ID)
        .append_pair(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )
        .append_pair("client_assertion", assertion)
        .append_pair("resource", RESOURCE)
        .append_pair("scope", "evidence:invoke")
        .finish();
    let mut process = std::process::Command::new("curl")
        .args([
            "--silent",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--max-time",
            "10",
            "--header",
            "Content-Type: application/x-www-form-urlencoded",
            "--data-binary",
            "@-",
            endpoint.as_str(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("curl is available");
    process
        .stdin
        .take()
        .expect("request stdin")
        .write_all(body.as_bytes())
        .expect("request body written");
    let output = process.wait_with_output().expect("request completes");
    output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "200"
}
