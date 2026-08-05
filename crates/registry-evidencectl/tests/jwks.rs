#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output},
};

fn evidencectl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path)
        .unwrap_or_else(|error| panic!("stat {}: {error}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf8 stderr")
}

/// Generates a signing keypair via the `keygen signing` subcommand and
/// returns the path to its public JWK file. Reuses the tool under test
/// instead of hand-rolling key material.
fn generate_public_jwk(dir: &Path, name: &str, kid: &str) -> std::path::PathBuf {
    let out_dir = dir.join(name);
    let output = evidencectl()
        .args(["keygen", "signing", "--out-dir"])
        .arg(&out_dir)
        .args(["--kid", kid])
        .output()
        .expect("run evidencectl keygen");
    assert!(output.status.success(), "{}", stderr_of(&output));
    out_dir.join("signing-ed25519-public.jwk.json")
}

#[test]
fn assembles_a_jwks_document_from_public_jwk_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = generate_public_jwk(dir.path(), "first", "kid-a");
    let second = generate_public_jwk(dir.path(), "second", "kid-b");
    let out = dir.path().join("jwks.json");

    let output = evidencectl()
        .arg("jwks")
        .arg("--out")
        .arg(&out)
        .arg(&first)
        .arg(&second)
        .output()
        .expect("run evidencectl jwks");
    assert!(output.status.success(), "{}", stderr_of(&output));

    assert_eq!(mode_of(&out), 0o644);
    let contents = fs::read_to_string(&out).expect("read jwks");
    assert!(contents.ends_with('\n'), "output must end with a newline");

    let document: serde_json::Value = serde_json::from_str(&contents).expect("valid json");
    let keys = document["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 2);
    let kids: Vec<&str> = keys
        .iter()
        .map(|key| key["kid"].as_str().unwrap())
        .collect();
    assert!(kids.contains(&"kid-a"));
    assert!(kids.contains(&"kid-b"));
}

#[test]
fn rejects_a_private_jwk_input_without_printing_its_contents() {
    let dir = tempfile::tempdir().expect("tempdir");
    let private_path = dir.path().join("oops-private.json");
    let canary = "s3cr3t-d-value-canary";
    fs::write(
        &private_path,
        format!(
            r#"{{"kty":"OKP","crv":"Ed25519","d":"{canary}","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"leaked"}}"#
        ),
    )
    .expect("write fake private jwk");
    let out = dir.path().join("jwks.json");

    let output = evidencectl()
        .arg("jwks")
        .arg("--out")
        .arg(&out)
        .arg(&private_path)
        .output()
        .expect("run evidencectl jwks");
    assert!(
        !output.status.success(),
        "private JWK input must be rejected"
    );
    assert!(!out.exists(), "no output should be written on rejection");

    let stderr = stderr_of(&output);
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(!stdout.contains(canary), "stdout leaked private material");
    assert!(!stderr.contains(canary), "stderr leaked private material");
}

#[test]
fn deduplicates_identical_duplicate_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let public = generate_public_jwk(dir.path(), "solo", "kid-dup");
    let out = dir.path().join("jwks.json");

    let output = evidencectl()
        .arg("jwks")
        .arg("--out")
        .arg(&out)
        .arg(&public)
        .arg(&public)
        .output()
        .expect("run evidencectl jwks");
    assert!(output.status.success(), "{}", stderr_of(&output));

    let contents = fs::read_to_string(&out).expect("read jwks");
    let document: serde_json::Value = serde_json::from_str(&contents).expect("valid json");
    let keys = document["keys"].as_array().expect("keys array");
    assert_eq!(
        keys.len(),
        1,
        "identical duplicate entries must be deduplicated"
    );
}

#[test]
fn conflicting_keys_sharing_a_kid_is_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = generate_public_jwk(dir.path(), "first", "shared-kid");
    let second = generate_public_jwk(dir.path(), "second", "shared-kid");
    let out = dir.path().join("jwks.json");

    let output = evidencectl()
        .arg("jwks")
        .arg("--out")
        .arg(&out)
        .arg(&first)
        .arg(&second)
        .output()
        .expect("run evidencectl jwks");
    assert!(
        !output.status.success(),
        "two different keys sharing a kid must be rejected"
    );
    assert!(!out.exists());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("shared-kid"),
        "error should name the conflicting kid: {stderr}"
    );
}

#[test]
fn force_replaces_a_symlinked_output_path_without_writing_through_it() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let public = generate_public_jwk(dir.path(), "solo", "kid-sym");
    let target = dir.path().join("elsewhere.json");
    fs::write(&target, b"untouched").expect("seed symlink target");
    let out = dir.path().join("jwks.json");
    symlink(&target, &out).expect("create symlink at the output path");

    let output = evidencectl()
        .arg("jwks")
        .arg("--out")
        .arg(&out)
        .arg("--force")
        .arg(&public)
        .output()
        .expect("run evidencectl jwks");
    assert!(output.status.success(), "{}", stderr_of(&output));

    let metadata = fs::symlink_metadata(&out).expect("stat output path");
    assert!(
        metadata.is_file(),
        "the symlink must be replaced by a regular file"
    );
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(mode_of(&out), 0o644);
    assert_eq!(
        fs::read(&target).expect("read symlink target"),
        b"untouched",
        "the symlink's former target must never be written through"
    );
}

#[test]
fn refuses_overwrite_without_force_then_succeeds_with_force() {
    let dir = tempfile::tempdir().expect("tempdir");
    let public = generate_public_jwk(dir.path(), "solo", "kid-x");
    let out = dir.path().join("jwks.json");

    let first = evidencectl()
        .arg("jwks")
        .arg("--out")
        .arg(&out)
        .arg(&public)
        .output()
        .expect("run evidencectl jwks");
    assert!(first.status.success(), "{}", stderr_of(&first));
    let original = fs::read(&out).expect("read jwks");

    let second = evidencectl()
        .arg("jwks")
        .arg("--out")
        .arg(&out)
        .arg(&public)
        .output()
        .expect("run evidencectl jwks");
    assert!(
        !second.status.success(),
        "overwrite without --force must be refused"
    );
    assert_eq!(fs::read(&out).expect("read jwks"), original);

    let another = generate_public_jwk(dir.path(), "another", "kid-y");
    let third = evidencectl()
        .arg("jwks")
        .arg("--out")
        .arg(&out)
        .arg("--force")
        .arg(&public)
        .arg(&another)
        .output()
        .expect("run evidencectl jwks");
    assert!(third.status.success(), "{}", stderr_of(&third));
    assert_eq!(mode_of(&out), 0o644);

    let contents = fs::read_to_string(&out).expect("read jwks");
    let document: serde_json::Value = serde_json::from_str(&contents).expect("valid json");
    assert_eq!(document["keys"].as_array().expect("keys array").len(), 2);
}
