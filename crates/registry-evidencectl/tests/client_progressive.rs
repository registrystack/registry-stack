use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output},
};

use serde_json::{json, Value};

/// The authorization server's issuer identifier, the client assertion's
/// audience.
const ISSUER: &str = "https://identity.example.test";

#[test]
fn profile_create_writes_the_strict_https_default_as_an_owner_only_file() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("client.json");
    let created = command()
        .args([
            "client",
            "profile",
            "create",
            "--base-url",
            "https://evidence.example.test/",
            "--client-id",
            "relying-party",
            "--private-key-file",
            "keys/client-private.jwk",
            "--client-assertion-audience",
            ISSUER,
            "--output",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert_success(&created);
    assert_eq!(mode(&output), 0o600);
    let profile: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(
        profile,
        json!({
            "apiVersion": "id.registrystack.org/formats/evidence/client-profile/v1",
            "kind": "EvidenceClientProfile",
            "baseUrl": "https://evidence.example.test",
            "clientId": "relying-party",
            "privateKey": {"type": "file", "path": "keys/client-private.jwk"},
            "trust": {"type": "https-discovery"},
            "contracts": {"type": "published"},
            "verification": {
                "maximumAssertionLifetimeSeconds": 300,
                "clockSkewSeconds": 30
            },
            "oauth": {"clientAssertionAudience": ISSUER}
        })
    );
    registry_evidence_client::EvidenceClientProfile::from_file(&output)
        .expect("created profile is accepted by the progressive client");
}

/// The client assertion audience is the authorization server's issuer
/// identifier (RFC 10070 section 4) and has no default, so a profile is not
/// created without it.
#[test]
fn profile_create_requires_the_client_assertion_audience() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("client.json");
    let refused = command()
        .args([
            "client",
            "profile",
            "create",
            "--base-url",
            "https://evidence.example.test/",
            "--client-id",
            "relying-party",
            "--private-key-file",
            "keys/client-private.jwk",
            "--output",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(
        refused.status.code(),
        Some(1),
        "a profile without an assertion audience was not refused"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("--client-assertion-audience"), "{stderr}");
    assert!(stderr.contains("issuer identifier"), "{stderr}");
    assert!(!output.exists());
}

#[test]
fn local_loopback_and_environment_keys_are_explicit() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("client.json");
    let created = command()
        .args([
            "client",
            "profile",
            "create",
            "--base-url",
            "http://127.0.0.1:8080/",
            "--client-id",
            "local-client",
            "--private-key-env",
            "EVIDENCE_CLIENT_PRIVATE_JWK",
            "--local-loopback-discovery",
            "--client-assertion-audience",
            "http://127.0.0.1:8091",
            "--output",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert_success(&created);
    let profile: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(
        profile["privateKey"],
        json!({"type": "environment", "variable": "EVIDENCE_CLIENT_PRIVATE_JWK"})
    );
    assert_eq!(
        profile["trust"],
        json!({"type": "local-loopback-discovery"})
    );
}

#[test]
fn unsafe_transport_paths_and_replacement_are_refused_without_echoing_paths() {
    let directory = tempfile::tempdir().unwrap();
    for (name, base_url, key_path, loopback) in [
        (
            "plain-http",
            "http://evidence.example.test/",
            "key.jwk",
            false,
        ),
        ("non-loopback", "http://192.0.2.1/", "key.jwk", true),
        (
            "missing-loopback-port",
            "http://127.0.0.1/",
            "key.jwk",
            true,
        ),
        ("zero-loopback-port", "http://127.0.0.1:0/", "key.jwk", true),
        (
            "traversal",
            "https://evidence.example.test/",
            "../key.jwk",
            false,
        ),
    ] {
        let output = directory.path().join(format!("{name}.json"));
        let mut command = command();
        command.args([
            "client",
            "profile",
            "create",
            "--base-url",
            base_url,
            "--client-id",
            "client",
            "--private-key-file",
            key_path,
            "--client-assertion-audience",
            ISSUER,
        ]);
        if loopback {
            command.arg("--local-loopback-discovery");
        }
        let refused = command.arg("--output").arg(&output).output().unwrap();
        assert!(!refused.status.success(), "{name} unexpectedly succeeded");
        let diagnostics = format!(
            "{}{}",
            String::from_utf8_lossy(&refused.stdout),
            String::from_utf8_lossy(&refused.stderr)
        );
        assert!(
            !diagnostics.contains(key_path),
            "sensitive path leaked: {diagnostics}"
        );
        assert!(!output.exists());
    }

    let existing = directory.path().join("existing.json");
    fs::write(&existing, b"do not replace").unwrap();
    let refused = profile_create(&existing);
    assert!(!refused.status.success());
    assert_eq!(fs::read(&existing).unwrap(), b"do not replace");
}

#[test]
fn profile_creation_enforces_the_sdk_client_identifier_bound() {
    let directory = tempfile::tempdir().unwrap();
    for (length, accepted) in [(256, true), (257, false)] {
        let output = directory.path().join(format!("client-{length}.json"));
        let client_id = "a".repeat(length);
        let result = command()
            .args([
                "client",
                "profile",
                "create",
                "--base-url",
                "https://evidence.example.test/",
                "--client-id",
                &client_id,
                "--private-key-file",
                "key.jwk",
                "--client-assertion-audience",
                ISSUER,
                "--output",
            ])
            .arg(&output)
            .output()
            .unwrap();
        assert_eq!(result.status.success(), accepted, "length {length}");
        assert_eq!(output.exists(), accepted, "length {length}");
        if accepted {
            registry_evidence_client::EvidenceClientProfile::from_file(&output)
                .expect("accepted profile remains usable by the SDK");
        }
    }
}

#[test]
fn profile_creation_refuses_invalid_expected_service_identities() {
    let directory = tempfile::tempdir().unwrap();
    for (name, option, value) in [
        ("audience", "--expected-audience", "not-a-uri".to_owned()),
        (
            "issuer",
            "--expected-issuer",
            format!("urn:{}", "a".repeat(509)),
        ),
        ("provider", "--expected-provider", String::new()),
    ] {
        let output = directory.path().join(format!("{name}.json"));
        let refused = command()
            .args([
                "client",
                "profile",
                "create",
                "--base-url",
                "https://evidence.example.test/",
                "--client-id",
                "client",
                "--private-key-file",
                "key.jwk",
                "--client-assertion-audience",
                ISSUER,
                option,
                &value,
                "--output",
            ])
            .arg(&output)
            .output()
            .unwrap();
        assert!(!refused.status.success(), "{name} unexpectedly succeeded");
        assert!(!output.exists());
    }
}

#[test]
fn the_progressive_client_help_is_complete() {
    for arguments in [
        &["client", "--help"][..],
        &["client", "profile", "create", "--help"][..],
        &["client", "contracts", "fetch", "--help"][..],
    ] {
        let output = command().args(arguments).output().unwrap();
        assert_success(&output);
    }
    let help = command()
        .args(["client", "profile", "create", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    for option in [
        "--base-url",
        "--client-id",
        "--private-key-file",
        "--private-key-env",
        "--local-loopback-discovery",
        "--client-assertion-audience",
        "--output",
    ] {
        assert!(help.contains(option), "missing {option}: {help}");
    }
}

#[tokio::test]
async fn progressive_remote_commands_apply_posture_to_discovery() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use axum::{http::StatusCode, routing::get, Json, Router};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let protected = json!({
        "resource": origin,
        "authorization_servers": [origin],
        "jwks_uri": format!("{origin}/.well-known/jwks.json"),
        "bearer_methods_supported": ["header"]
    });
    let later_requests = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&later_requests);
    let app = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(move || {
                let protected = protected.clone();
                async move { ([("registry-posture", "development")], Json(protected)) }
            }),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(move || {
                let observed = Arc::clone(&observed);
                async move {
                    observed.fetch_add(1, Ordering::Relaxed);
                    StatusCode::NOT_FOUND
                }
            }),
        );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("client.json");
    let key_file = directory.path().join("client.jwk");
    let signing = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let point = signing.verifying_key().to_sec1_point(false);
    let key = json!({
        "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "synthetic-client",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        "d": URL_SAFE_NO_PAD.encode(signing.to_bytes()),
    });
    fs::write(&key_file, serde_json::to_vec(&key).unwrap()).unwrap();
    fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    let profile_document = json!({
        "apiVersion": "id.registrystack.org/formats/evidence/client-profile/v1",
        "kind": "EvidenceClientProfile",
        "baseUrl": origin,
        "clientId": "synthetic-client",
        "privateKey": {"type": "file", "path": "client.jwk"},
        "trust": {"type": "local-loopback-discovery"},
        "oauth": {"clientAssertionAudience": origin}
    });
    fs::write(&profile, serde_json::to_vec(&profile_document).unwrap()).unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o600)).unwrap();
    let candidate = directory.path().join("contracts.json");
    for args in [
        vec![
            "client",
            "contracts",
            "fetch",
            "--output",
            candidate.to_str().unwrap(),
        ],
        vec![
            "request",
            "prepare",
            "--requirement",
            "urn:example:requirement",
            "--name",
            "synthetic",
            "--subject",
            "id=synthetic",
        ],
    ] {
        for (posture, expected_next_requests) in [("production", 0), ("development", 1)] {
            later_requests.store(0, Ordering::Relaxed);
            let output = tokio::process::Command::from(command())
                .current_dir(directory.path())
                .args(&args)
                .arg("--profile")
                .arg(&profile)
                .args(["--posture", posture])
                .env_remove("REGISTRY_STACK_POSTURE")
                .output()
                .await
                .unwrap();
            assert_eq!(
                later_requests.load(Ordering::Relaxed),
                expected_next_requests,
                "{args:?} {posture}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !output.status.success(),
                "the authorization metadata is unavailable"
            );
            assert!(!candidate.exists());
        }
    }
    server.abort();
}

#[test]
fn unsafe_profile_permissions_fail_before_network_or_artifact_creation() {
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("client.json");
    fs::write(
        &profile,
        br#"{"apiVersion":"id.registrystack.org/formats/evidence/client-profile/v1","kind":"EvidenceClientProfile","baseUrl":"https://evidence.example.test/","clientId":"client","privateKey":{"type":"environment","variable":"EVIDENCE_KEY"},"trust":{"type":"https-discovery"},"contracts":{"type":"published"},"verification":{"maximumAssertionLifetimeSeconds":300,"clockSkewSeconds":30},"oauth":{"clientAssertionAudience":"https://identity.example.test"}}"#,
    )
    .unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o644)).unwrap();
    let out = directory.path().join("contracts.json");
    let refused = command()
        .args(["client", "contracts", "fetch", "--profile"])
        .arg(&profile)
        .arg("--output")
        .arg(&out)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(!out.exists());
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(!diagnostics.contains(profile.to_str().unwrap()));
}

fn profile_create(output: &Path) -> Output {
    command()
        .args([
            "client",
            "profile",
            "create",
            "--base-url",
            "https://evidence.example.test/",
            "--client-id",
            "client",
            "--private-key-file",
            "key.jwk",
            "--client-assertion-audience",
            ISSUER,
            "--output",
        ])
        .arg(output)
        .output()
        .unwrap()
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn the_retired_out_spelling_of_output_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("client.json");
    for arguments in [
        vec![
            "client",
            "profile",
            "create",
            "--base-url",
            "https://evidence.example.test/",
            "--client-id",
            "relying-party",
            "--private-key-file",
            "keys/client-private.jwk",
            "--client-assertion-audience",
            ISSUER,
        ],
        vec!["client", "contracts", "fetch", "--profile", "profile.json"],
    ] {
        let refused = command()
            .args(&arguments)
            .arg("--out")
            .arg(&output)
            .output()
            .unwrap();
        assert!(!refused.status.success(), "{arguments:?} accepted --out");
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            stderr.contains("evidencectl.usage"),
            "{arguments:?}: {stderr}"
        );
        assert!(!output.exists());
    }
}
