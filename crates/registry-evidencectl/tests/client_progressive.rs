use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output},
};

use serde_json::{json, Value};

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
            "--out",
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
            "schema": "registry.evidence-client-profile/v1",
            "baseUrl": "https://evidence.example.test",
            "clientId": "relying-party",
            "privateKey": {"source": "file", "path": "keys/client-private.jwk"},
            "trust": {"type": "https-discovery"},
            "contracts": {"type": "published"},
            "verification": {
                "maximumAssertionLifetimeSeconds": 300,
                "clockSkewSeconds": 30
            }
        })
    );
    registry_evidence_client::EvidenceClientProfile::from_file(&output)
        .expect("created profile is accepted by the progressive client");
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
            "--out",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert_success(&created);
    let profile: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(
        profile["privateKey"],
        json!({"source": "environment", "variable": "EVIDENCE_CLIENT_PRIVATE_JWK"})
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
        ]);
        if loopback {
            command.arg("--local-loopback-discovery");
        }
        let refused = command.arg("--out").arg(&output).output().unwrap();
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
                "--out",
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
        "--out",
    ] {
        assert!(help.contains(option), "missing {option}: {help}");
    }
}

#[test]
fn unsafe_profile_permissions_fail_before_network_or_artifact_creation() {
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("client.json");
    fs::write(
        &profile,
        br#"{"schema":"registry.evidence-client-profile/v1","baseUrl":"https://evidence.example.test/","clientId":"client","privateKey":{"source":"environment","variable":"EVIDENCE_KEY"},"trust":{"type":"https-discovery"},"contracts":{"type":"published"},"verification":{"maximumAssertionLifetimeSeconds":300,"clockSkewSeconds":30}}"#,
    )
    .unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o644)).unwrap();
    let out = directory.path().join("contracts.json");
    let refused = command()
        .args(["client", "contracts", "fetch", "--profile"])
        .arg(&profile)
        .arg("--out")
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
            "--out",
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
