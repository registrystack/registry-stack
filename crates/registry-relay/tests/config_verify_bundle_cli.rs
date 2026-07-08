// SPDX-License-Identifier: Apache-2.0
//! CLI coverage for config bundle v1 verification.

use std::path::PathBuf;
use std::process::Command;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_config::{
    sha256_uri, ConfigBundleFile, ConfigBundleManifest, ConfigBundleSignature,
    ConfigBundleSignatureEnvelope, ConfigTrustAnchor, ConfigTrustAnchorSigner,
};
use registry_platform_crypto::{canonicalize_json, sign, PrivateJwk};
use registry_platform_ops::{
    AntiRollbackKey, AntiRollbackRecord, ConfigOverrideMode, ConfigOverridePin,
    FileAntiRollbackStore,
};
use serde_json::Value;
use tempfile::TempDir;

const PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

struct BundleFixture {
    bundle_dir: PathBuf,
    anchor_path: PathBuf,
    state_path: PathBuf,
    config_path: PathBuf,
    config_hash: String,
}

#[test]
fn config_verify_bundle_cli_reports_verified_signed_bundle() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-relay", 0);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = stdout_json(&output);
    assert_eq!(report["result"], "verified");
    assert_eq!(report["component"], "registry-relay");
    assert_eq!(report["stream_id"], "relay-test-stream");
    assert_eq!(report["bundle_id"], "relay-test-bundle");
    assert_eq!(report["bundle_sequence"], 1);
    assert_eq!(report["config_hash"], fixture.config_hash);
}

#[test]
fn config_verify_bundle_cli_reports_rejected_rollback() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-relay", 2);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_rollback");
    assert_eq!(report["errors"][0]["code"], "rejected_rollback");
}

#[test]
fn config_verify_bundle_cli_rejects_expired_override_pin() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-relay", 2);
    std::fs::write(
        &fixture.state_path,
        serde_json::to_vec_pretty(&AntiRollbackRecord {
            key: AntiRollbackKey {
                product: "registry-relay".to_string(),
                instance_id: "relay-lab".to_string(),
                environment: "lab".to_string(),
                stream_id: "relay-test-stream".to_string(),
            },
            last_sequence: 2,
            last_config_hash:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            last_bundle_id: None,
            root_version: None,
            override_pin: Some(ConfigOverridePin {
                active: true,
                mode: ConfigOverrideMode::AcceptRollback,
                config_hash: fixture.config_hash.clone(),
                config_path: None,
                expires_at: Some("2026-07-07T10:00:00Z".to_string()),
                used_at: "2026-07-07T09:00:00Z".to_string(),
                operator: "jeremi".to_string(),
                reason: "expired rollback".to_string(),
            }),
            break_glass: Default::default(),
            local_approvals: Default::default(),
        })
        .expect("state serializes"),
    )
    .expect("state writes");

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_rollback");
    assert_eq!(report["errors"][0]["code"], "rejected_rollback");
}

#[test]
fn config_verify_bundle_cli_reports_rejected_binding() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-notary", 0);

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_binding");
    assert_eq!(report["errors"][0]["code"], "rejected_binding");
}

#[test]
fn config_verify_bundle_cli_reports_rejected_validation() {
    let temp = TempDir::new().expect("tempdir");
    let fixture = write_bundle_fixture(&temp, "registry-relay", 0);
    std::fs::write(&fixture.config_path, b"changed config bytes").expect("config changes");

    let output = verify_bundle_command(&fixture)
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let report = stdout_json(&output);
    assert_eq!(report["result"], "rejected_validation");
    assert_eq!(report["errors"][0]["code"], "rejected_validation");
}

fn verify_bundle_command(fixture: &BundleFixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-relay"));
    command.args([
        "config",
        "verify-bundle",
        "--bundle-dir",
        fixture.bundle_dir.to_str().expect("path is UTF-8"),
        "--anchor-path",
        fixture.anchor_path.to_str().expect("path is UTF-8"),
        "--state-path",
        fixture.state_path.to_str().expect("path is UTF-8"),
    ]);
    command
}

fn write_bundle_fixture(
    temp: &TempDir,
    manifest_product: &str,
    last_sequence: u64,
) -> BundleFixture {
    let bundle_dir = temp.path().join("bundle");
    let config_dir = bundle_dir.join("config");
    std::fs::create_dir_all(&config_dir).expect("bundle config dir");
    let config_path = config_dir.join("relay.yaml");
    let config = relay_config_yaml();
    std::fs::write(&config_path, config.as_bytes()).expect("config writes");
    let config_hash = sha256_uri(config.as_bytes());

    let private = PrivateJwk::parse(PRIVATE_JWK).expect("private JWK parses");
    let public = private.public();
    let kid = public.jkt().expect("thumbprint computes");
    let manifest = ConfigBundleManifest {
        schema: "registry.platform.config_bundle.v1".to_string(),
        product: manifest_product.to_string(),
        environment: "lab".to_string(),
        stream_id: "relay-test-stream".to_string(),
        instance_id: None,
        bundle_id: "relay-test-bundle".to_string(),
        sequence: 1,
        previous_config_hash: Some(ZERO_HASH.to_string()),
        config_hash: config_hash.clone(),
        files: vec![ConfigBundleFile {
            path: "config/relay.yaml".to_string(),
            sha256: config_hash.clone(),
        }],
        created_at: "2026-07-07T10:00:00Z".to_string(),
    };
    write_manifest_and_signature(&bundle_dir, &manifest, &private, &kid);

    let anchor = ConfigTrustAnchor {
        schema: "registry.platform.config_trust_anchor.v1".to_string(),
        product: "registry-relay".to_string(),
        environment: "lab".to_string(),
        stream_id: "relay-test-stream".to_string(),
        instance_id: "relay-lab".to_string(),
        signers: vec![ConfigTrustAnchorSigner {
            kid,
            jwk: public,
            enabled: true,
        }],
    };
    let anchor_path = temp.path().join("trust_anchor.json");
    std::fs::write(
        &anchor_path,
        serde_json::to_vec_pretty(&anchor).expect("anchor serializes"),
    )
    .expect("anchor writes");

    let state_path = temp.path().join("antirollback.json");
    FileAntiRollbackStore::new(&state_path)
        .initialize(AntiRollbackRecord {
            key: AntiRollbackKey {
                product: "registry-relay".to_string(),
                instance_id: "relay-lab".to_string(),
                environment: "lab".to_string(),
                stream_id: "relay-test-stream".to_string(),
            },
            last_sequence,
            last_config_hash: if last_sequence == 0 {
                ZERO_HASH.to_string()
            } else {
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string()
            },
            last_bundle_id: None,
            root_version: None,
            override_pin: None,
            break_glass: Default::default(),
            local_approvals: Default::default(),
        })
        .expect("state initializes");

    BundleFixture {
        bundle_dir,
        anchor_path,
        state_path,
        config_path,
        config_hash,
    }
}

fn write_manifest_and_signature(
    bundle_dir: &std::path::Path,
    manifest: &ConfigBundleManifest,
    private: &PrivateJwk,
    kid: &str,
) {
    let manifest_value = serde_json::to_value(manifest).expect("manifest value");
    let canonical = canonicalize_json(&manifest_value).expect("canonical manifest");
    let signature = sign(&canonical, private).expect("manifest signs");
    let envelope = ConfigBundleSignatureEnvelope {
        schema: "registry.platform.config_bundle_signatures.v1".to_string(),
        signatures: vec![ConfigBundleSignature {
            kid: kid.to_string(),
            alg: "EdDSA".to_string(),
            sig: URL_SAFE_NO_PAD.encode(signature),
        }],
    };
    std::fs::write(
        bundle_dir.join("manifest.json"),
        serde_json::to_vec_pretty(manifest).expect("manifest serializes"),
    )
    .expect("manifest writes");
    std::fs::write(
        bundle_dir.join("manifest.sig.json"),
        serde_json::to_vec_pretty(&envelope).expect("signature serializes"),
    )
    .expect("signature writes");
}

fn stdout_json(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn relay_config_yaml() -> String {
    r#"
instance:
  id: relay-lab
  environment: lab
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {}
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: stdout
"#
    .to_string()
}
