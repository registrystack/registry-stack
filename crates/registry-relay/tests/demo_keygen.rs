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

perf = load("generate_perf_keys_replace", "perf/scripts/generate_perf_keys.py")
target = targets[1]
target.write_text("old secret material")
target.chmod(0o644)
old_inode = target.stat().st_ino
with target.open() as old_file:
    perf.write_secret_file(target, "secret")
    assert old_file.read() == "old secret material"
assert target.stat().st_ino != old_inode
assert stat.S_IMODE(target.stat().st_mode) == 0o600
assert target.read_text() == "secret"
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
