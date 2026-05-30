// SPDX-License-Identifier: Apache-2.0
//! Focused checks for demo secret generation.

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

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success())
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
    let tmp = TempDir::new().expect("tempdir");
    let env_file = tmp.path().join("demo.env");
    let bruno_env = root.join("bruno/registry-relay-demo/.env");
    let _ = std::fs::remove_file(&bruno_env);

    let output = Command::new(python())
        .current_dir(&root)
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

    std::fs::remove_file(bruno_env).expect("remove generated bruno env");
}

#[test]
fn write_secret_file_restricts_existing_file_before_writing() {
    let root = repo_root();
    let tmp = TempDir::new().expect("tempdir");
    let env_file = tmp.path().join("demo.env");
    std::fs::write(&env_file, "old").expect("seed loose file");
    std::fs::set_permissions(&env_file, std::fs::Permissions::from_mode(0o644))
        .expect("loosen seed file");

    let verifier = r#"
import importlib.util
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
target = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location(
    "generate_demo_keys", root / "demo/scripts/generate_demo_keys.py"
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

real_fdopen = module.os.fdopen
observed_modes = []

def checked_fdopen(fd, *args, **kwargs):
    observed_modes.append(stat.S_IMODE(os.fstat(fd).st_mode))
    return real_fdopen(fd, *args, **kwargs)

module.os.fdopen = checked_fdopen
module.write_secret_file(target, "secret")
assert observed_modes == [0o600], observed_modes
assert stat.S_IMODE(target.stat().st_mode) == 0o600
assert target.read_text() == "secret"
"#;

    let output = Command::new(python())
        .current_dir(&root)
        .arg("-c")
        .arg(verifier)
        .arg(&root)
        .arg(&env_file)
        .output()
        .expect("write_secret_file verifier runs");

    assert!(
        output.status.success(),
        "write_secret_file verifier failed\nstdout:\n{}\nstderr:\n{}",
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
fn decentralized_secret_generator_writes_env_file_0600() {
    if !openssl_available() {
        eprintln!("skipping decentralized secret permission check: openssl is not on PATH");
        return;
    }

    let root = repo_root();
    let tmp = TempDir::new().expect("tempdir");
    let env_file = tmp.path().join("decentralized.env");

    let output = Command::new(python())
        .current_dir(&root)
        .arg("demo/decentralized/scripts/generate-demo-secrets.py")
        .arg("--env-file")
        .arg(&env_file)
        .output()
        .expect("decentralized secret generator runs");

    assert!(
        output.status.success(),
        "decentralized secret generator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_mode_0600(&env_file);
    let contents = std::fs::read_to_string(&env_file).expect("env file readable");
    assert!(contents.contains("REGISTRY_RELAY_AUDIT_HASH_SECRET="));
    assert!(!contents.contains("2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"));
}
