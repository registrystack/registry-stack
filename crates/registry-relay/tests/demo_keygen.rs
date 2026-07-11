// SPDX-License-Identifier: Apache-2.0
//! Focused checks for demo secret generation.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn python() -> String {
    let configured = std::env::var("PYTHON").unwrap_or_else(|_| "python3".to_string());
    let output = Command::new(&configured)
        .arg("-c")
        .arg("import sys; print(sys.executable)")
        .output()
        .expect("python resolves");
    assert!(
        output.status.success(),
        "python probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("python path is utf-8")
        .trim()
        .to_string()
}

fn assert_mode_0600(path: &Path) {
    let mode = std::fs::metadata(path)
        .expect("file metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "{} mode should be 0600", path.display());
}

fn read_env_file(path: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("{} should be readable: {err}", path.display()))
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (key, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("{} contains invalid env line: {line}", path.display()));
            (key.to_string(), value.to_string())
        })
        .collect()
}

fn assert_exact_env_keys(path: &Path, expected: &[&str]) -> BTreeMap<String, String> {
    let values = read_env_file(path);
    let actual_keys: Vec<&str> = values.keys().map(String::as_str).collect();
    assert_eq!(
        actual_keys,
        expected,
        "{} should contain only the expected scoped variables",
        path.display()
    );
    values
}

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("destination directory");
    for entry in std::fs::read_dir(src).expect("source directory readable") {
        let entry = entry.expect("source directory entry");
        let source = entry.path();
        let target = dst.join(entry.file_name());
        let file_type = entry.file_type().expect("entry file type");
        if file_type.is_dir() {
            copy_dir_recursive(&source, &target);
        } else if file_type.is_file() {
            std::fs::copy(&source, &target).unwrap_or_else(|err| {
                panic!(
                    "copy {} to {} failed: {err}",
                    source.display(),
                    target.display()
                )
            });
        }
    }
}

fn isolated_demo_keygen_root(repo: &Path) -> TempDir {
    let tmp = TempDir::new().expect("tempdir");
    let scripts = tmp.path().join("demo/scripts");
    std::fs::create_dir_all(&scripts).expect("isolated demo scripts dir");
    std::fs::copy(
        repo.join("demo/scripts/generate_demo_keys.py"),
        scripts.join("generate_demo_keys.py"),
    )
    .expect("copy demo key generator");
    copy_dir_recursive(&repo.join("demo/config"), &tmp.path().join("demo/config"));
    tmp
}

#[test]
fn generated_demo_holder_proofs_verify_with_embedded_public_jwk() {
    if !openssl_available() {
        eprintln!("skipping demo holder proof verification: openssl is not on PATH");
        return;
    }

    let root = repo_root();
    let verifier = r#"
import base64
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(sys.argv[1])

def load_module(name, relative):
    spec = importlib.util.spec_from_file_location(name, root / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def verify(holder_id, jwt):
    parts = jwt.split(".")
    assert len(parts) == 3, jwt
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    assert header["alg"] == "EdDSA"
    assert header["kid"] == holder_id
    assert payload["sub"] == holder_id
    assert holder_id.startswith("did:jwk:")
    public_jwk = json.loads(b64url_decode(holder_id.removeprefix("did:jwk:")))
    public_key = b64url_decode(public_jwk["x"])
    spki_der = bytes.fromhex("302a300506032b6570032100") + public_key
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        der = tmp / "pub.der"
        pem = tmp / "pub.pem"
        signing_input = tmp / "input"
        signature = tmp / "sig"
        der.write_bytes(spki_der)
        signing_input.write_bytes(f"{parts[0]}.{parts[1]}".encode("ascii"))
        signature.write_bytes(b64url_decode(parts[2]))
        subprocess.run(
            ["openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(der), "-out", str(pem)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(pem),
                "-rawin",
                "-in",
                str(signing_input),
                "-sigfile",
                str(signature),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

registry = load_module("registry_notary_demo", "demo/scripts/registry_notary_demo.py")
holder_id, jwt = registry.sign_holder_proof("eval-1", "profile", "predicate", ["claim"])
verify(holder_id, jwt)

decentralized = load_module("decentralized_demo_flow", "demo/decentralized/scripts/demo-flow.py")
holder_id, jwt = decentralized.sign_holder_proof("eval-1", "profile", ["claim"])
verify(holder_id, jwt)
"#;

    let output = Command::new(python())
        .current_dir(&root)
        .arg("-c")
        .arg(verifier)
        .arg(&root)
        .output()
        .expect("holder proof verifier runs");

    assert!(
        output.status.success(),
        "holder proof verification failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn demo_flows_do_not_embed_static_ed25519_fallbacks() {
    let root = repo_root();
    for script in [
        "demo/scripts/registry_notary_demo.py",
        "demo/decentralized/scripts/demo-flow.py",
    ] {
        let contents = std::fs::read_to_string(root.join(script)).expect("script readable");
        assert!(
            !contents.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"),
            "{script} must not embed the old issuer private scalar"
        );
        assert!(
            !contents.contains("MC4CAQAwBQYDK2VwBCIEINpAgYVDwfGjJ/3AJ6IKwVqB8vpnxoX4E4RbnLSFarM+"),
            "{script} must not embed the old holder private key"
        );
        assert!(
            !contents.contains("gpb08DSqiqOybeHIDCLRcPdnDbhGL1ypfkLEFd977d8"),
            "{script} must not embed the old holder public key"
        );
    }
}

#[test]
fn demo_key_generator_writes_secret_files_0600() {
    if !openssl_available() {
        eprintln!("skipping demo keygen permission check: openssl is not on PATH");
        return;
    }

    let root = repo_root();
    let isolated = isolated_demo_keygen_root(&root);
    let env_file = isolated.path().join("demo.env");
    let bruno_env = isolated.path().join("bruno/registry-relay-demo/.env");

    let output = Command::new(python())
        .current_dir(isolated.path())
        .arg("demo/scripts/generate_demo_keys.py")
        .arg("--env-file")
        .arg(&env_file)
        .output()
        .expect("demo key generator runs");

    assert!(
        output.status.success(),
        "demo key generator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_mode_0600(&env_file);
    assert_mode_0600(&bruno_env);

    let contents = std::fs::read_to_string(&env_file).expect("env file readable");
    assert!(contents.contains("REGISTRY_NOTARY_ISSUER_JWK="));
    assert!(!contents.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
}

#[test]
fn key_generators_restrict_existing_secret_files_before_writing() {
    let root = repo_root();
    let tmp = TempDir::new().expect("tempdir");
    let demo_env_file = tmp.path().join("demo.env");
    let perf_env_file = tmp.path().join("perf.env");
    for env_file in [&demo_env_file, &perf_env_file] {
        std::fs::write(env_file, "old").expect("seed loose file");
        std::fs::set_permissions(env_file, std::fs::Permissions::from_mode(0o644))
            .expect("loosen seed file");
    }

    let verifier = r#"
import importlib.util
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
targets = [Path(sys.argv[2]), Path(sys.argv[3])]

def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, root / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module

for module, target in zip([
    load("generate_demo_keys", "demo/scripts/generate_demo_keys.py"),
    load("generate_perf_keys", "perf/scripts/generate_perf_keys.py"),
], targets):
    real_fdopen = module.os.fdopen
    observed_modes = []

    def checked_fdopen(fd, *args, **kwargs):
        observed_modes.append(stat.S_IMODE(os.fstat(fd).st_mode))
        return real_fdopen(fd, *args, **kwargs)

    try:
        module.os.fdopen = checked_fdopen
        module.write_secret_file(target, "secret")
    finally:
        module.os.fdopen = real_fdopen
    assert observed_modes == [0o600], (module.__name__, observed_modes)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600, module.__name__
    assert target.read_text() == "secret", module.__name__
"#;

    let output = Command::new(python())
        .current_dir(&root)
        .arg("-c")
        .arg(verifier)
        .arg(&root)
        .arg(&demo_env_file)
        .arg(&perf_env_file)
        .output()
        .expect("secret file verifier runs");

    assert!(
        output.status.success(),
        "secret file verifier failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn key_generators_refresh_quoted_credential_refs() {
    let root = repo_root();
    let verifier = r#"
import importlib.util
import sys
import types
from pathlib import Path

root = Path(sys.argv[1])

def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, root / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module

cryptography = types.ModuleType("cryptography")
hazmat = types.ModuleType("cryptography.hazmat")
primitives = types.ModuleType("cryptography.hazmat.primitives")
serialization = types.ModuleType("cryptography.hazmat.primitives.serialization")
asymmetric = types.ModuleType("cryptography.hazmat.primitives.asymmetric")
ed25519 = types.ModuleType("cryptography.hazmat.primitives.asymmetric.ed25519")
ed25519.Ed25519PrivateKey = object
primitives.serialization = serialization
asymmetric.ed25519 = ed25519
sys.modules["cryptography"] = cryptography
sys.modules["cryptography.hazmat"] = hazmat
sys.modules["cryptography.hazmat.primitives"] = primitives
sys.modules["cryptography.hazmat.primitives.serialization"] = serialization
sys.modules["cryptography.hazmat.primitives.asymmetric"] = asymmetric
sys.modules["cryptography.hazmat.primitives.asymmetric.ed25519"] = ed25519

for module in [
    load("generate_demo_keys", "demo/scripts/generate_demo_keys.py"),
    load("generate_perf_keys", "perf/scripts/generate_perf_keys.py"),
]:
    assert not hasattr(module, "credential_commitment"), module.__name__
    assert not hasattr(module, "refresh_credential_block"), module.__name__
"#;

    let output = Command::new(python())
        .current_dir(&root)
        .arg("-c")
        .arg(verifier)
        .arg(&root)
        .output()
        .expect("quoted credential verifier runs");

    assert!(
        output.status.success(),
        "quoted credential verifier failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn demo_key_generator_fails_loudly_when_openssl_is_missing() {
    let root = repo_root();
    let tmp = TempDir::new().expect("tempdir");
    let env_file = tmp.path().join("should-not-exist.env");

    let output = Command::new(python())
        .current_dir(&root)
        .env("PATH", tmp.path())
        .arg("demo/scripts/generate_demo_keys.py")
        .arg("--env-file")
        .arg(&env_file)
        .output()
        .expect("demo key generator runs");

    assert!(!output.status.success(), "keygen must fail without openssl");
    assert!(!env_file.exists(), "failed keygen must not write env file");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("openssl Ed25519 key generation failed"),
        "stderr should explain keygen failure, got: {stderr}"
    );
}

#[test]
fn decentralized_secret_generator_writes_scoped_env_files_0600() {
    if !openssl_available() {
        eprintln!("skipping decentralized secret permission check: openssl is not on PATH");
        return;
    }

    let root = repo_root();
    let tmp = TempDir::new().expect("tempdir");
    let env_dir = tmp.path().join("env");

    let output = Command::new(python())
        .current_dir(&root)
        .arg("demo/decentralized/scripts/generate-demo-secrets.py")
        .arg("--env-dir")
        .arg(&env_dir)
        .output()
        .expect("decentralized secret generator runs");

    assert!(
        output.status.success(),
        "decentralized secret generator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let civil_relay = env_dir.join("civil-registry-relay.env");
    let social_relay = env_dir.join("social-protection-registry-relay.env");
    let health_relay = env_dir.join("health-registry-relay.env");
    let civil_notary = env_dir.join("civil-registry-notary.env");
    let social_notary = env_dir.join("social-protection-registry-notary.env");
    let shared_notary = env_dir.join("shared-eligibility-registry-notary.env");
    let demo_client = env_dir.join("demo-client.env");

    for path in [
        &civil_relay,
        &social_relay,
        &health_relay,
        &civil_notary,
        &social_notary,
        &shared_notary,
        &demo_client,
    ] {
        assert_mode_0600(path);
    }

    let civil_relay_values = assert_exact_env_keys(
        &civil_relay,
        &[
            "CIVIL_EVIDENCE_ONLY_HASH",
            "CIVIL_EVIDENCE_SOURCE_HASH",
            "CIVIL_METADATA_CLIENT_HASH",
            "CIVIL_ROW_READER_HASH",
            "REGISTRY_RELAY_AUDIT_HASH_SECRET",
            "SHARED_CIVIL_EVIDENCE_SOURCE_HASH",
        ],
    );
    let social_relay_values = assert_exact_env_keys(
        &social_relay,
        &[
            "REGISTRY_RELAY_AUDIT_HASH_SECRET",
            "SHARED_SOCIAL_EVIDENCE_SOURCE_HASH",
            "SOCIAL_AGGREGATE_READER_HASH",
            "SOCIAL_EVIDENCE_ONLY_HASH",
            "SOCIAL_EVIDENCE_SOURCE_HASH",
            "SOCIAL_METADATA_CLIENT_HASH",
            "SOCIAL_ROW_READER_HASH",
        ],
    );
    let health_relay_values = assert_exact_env_keys(
        &health_relay,
        &[
            "HEALTH_EVIDENCE_ONLY_HASH",
            "HEALTH_EVIDENCE_SOURCE_HASH",
            "HEALTH_METADATA_CLIENT_HASH",
            "HEALTH_ROW_READER_HASH",
            "REGISTRY_RELAY_AUDIT_HASH_SECRET",
            "SHARED_HEALTH_EVIDENCE_SOURCE_HASH",
        ],
    );
    let civil_notary_values = assert_exact_env_keys(
        &civil_notary,
        &[
            "CIVIL_EVIDENCE_CLIENT_BEARER_HASH",
            "CIVIL_EVIDENCE_CLIENT_TOKEN_HASH",
            "CIVIL_EVIDENCE_ISSUER_JWK",
            "CIVIL_EVIDENCE_SOURCE_RAW",
        ],
    );
    let social_notary_values = assert_exact_env_keys(
        &social_notary,
        &[
            "SOCIAL_EVIDENCE_CLIENT_BEARER_HASH",
            "SOCIAL_EVIDENCE_CLIENT_TOKEN_HASH",
            "SOCIAL_EVIDENCE_SOURCE_RAW",
            "SOCIAL_PROTECTION_EVIDENCE_ISSUER_JWK",
        ],
    );
    let shared_notary_values = assert_exact_env_keys(
        &shared_notary,
        &[
            "SHARED_CIVIL_EVIDENCE_SOURCE_RAW",
            "SHARED_ELIGIBILITY_EVIDENCE_ISSUER_JWK",
            "SHARED_EVIDENCE_CLIENT_BEARER_HASH",
            "SHARED_EVIDENCE_CLIENT_TOKEN_HASH",
            "SHARED_HEALTH_EVIDENCE_SOURCE_RAW",
            "SHARED_SOCIAL_EVIDENCE_SOURCE_RAW",
        ],
    );
    let demo_client_values = assert_exact_env_keys(
        &demo_client,
        &[
            "CIVIL_EVIDENCE_CLIENT_BEARER",
            "CIVIL_METADATA_CLIENT_RAW",
            "HEALTH_METADATA_CLIENT_RAW",
            "SHARED_EVIDENCE_CLIENT_BEARER",
            "SOCIAL_AGGREGATE_READER_RAW",
            "SOCIAL_EVIDENCE_CLIENT_BEARER",
            "SOCIAL_EVIDENCE_ONLY_RAW",
            "SOCIAL_METADATA_CLIENT_RAW",
            "SOCIAL_ROW_READER_RAW",
        ],
    );

    for values in [
        &civil_relay_values,
        &social_relay_values,
        &health_relay_values,
    ] {
        assert!(
            values
                .keys()
                .all(|key| key.ends_with("_HASH") || key == "REGISTRY_RELAY_AUDIT_HASH_SECRET"),
            "relay env files must contain only hashes plus audit hash secret"
        );
        assert!(
            values.keys().all(|key| !key.ends_with("_RAW")
                && !key.ends_with("_TOKEN")
                && !key.ends_with("_BEARER")
                && !key.contains("JWK")),
            "relay env files must not receive raw tokens or issuer keys"
        );
    }
    assert!(
        demo_client_values
            .keys()
            .all(|key| !key.ends_with("_HASH") && !key.contains("JWK")),
        "demo client env file must not receive hashes or issuer keys"
    );
    for values in [
        &civil_notary_values,
        &social_notary_values,
        &shared_notary_values,
    ] {
        assert!(
            values.keys().all(|key| {
                !key.ends_with("_TOKEN") && !key.ends_with("_BEARER") && !key.ends_with("_RAW")
                    || key.ends_with("_SOURCE_RAW")
                    || key.starts_with("SHARED_") && key.ends_with("_EVIDENCE_SOURCE_RAW")
            }),
            "notary env files must not receive raw client credentials"
        );
        assert!(
            values.keys().all(|key| !key.ends_with("_COMMITMENT")),
            "notary env files must not receive removed credential commitments"
        );
    }
    assert_ne!(
        civil_notary_values["CIVIL_EVIDENCE_ISSUER_JWK"],
        social_notary_values["SOCIAL_PROTECTION_EVIDENCE_ISSUER_JWK"]
    );
    assert_ne!(
        civil_notary_values["CIVIL_EVIDENCE_ISSUER_JWK"],
        shared_notary_values["SHARED_ELIGIBILITY_EVIDENCE_ISSUER_JWK"]
    );
    assert_ne!(
        social_notary_values["SOCIAL_PROTECTION_EVIDENCE_ISSUER_JWK"],
        shared_notary_values["SHARED_ELIGIBILITY_EVIDENCE_ISSUER_JWK"]
    );
    let combined_contents =
        std::fs::read_to_string(civil_notary).expect("civil notary env readable");
    assert!(!combined_contents.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
}
