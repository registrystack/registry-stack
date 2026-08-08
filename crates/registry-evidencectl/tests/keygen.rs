#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output},
};

use registry_platform_crypto::{PrivateJwk, PublicJwk};

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

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf8 stdout")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf8 stderr")
}

/// Asserts neither captured stream contains `needle`, e.g. private key
/// material that must never reach the terminal or logs.
fn assert_output_excludes(output: &Output, needle: &str) {
    let stdout = stdout_of(output);
    let stderr = stderr_of(output);
    assert!(
        !stdout.contains(needle),
        "stdout leaked secret material: {stdout}"
    );
    assert!(
        !stderr.contains(needle),
        "stderr leaked secret material: {stderr}"
    );
}

#[test]
fn signing_writes_private_and_public_jwk_with_expected_modes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");

    let output = evidencectl()
        .args(["keygen", "signing", "--out-dir"])
        .arg(&out_dir)
        .output()
        .expect("run evidencectl");
    assert!(
        output.status.success(),
        "keygen signing failed: {}",
        stderr_of(&output)
    );

    assert_eq!(mode_of(&out_dir), 0o700, "out-dir mode");

    let private_path = out_dir.join("signing-p256-private-jwk");
    let public_path = out_dir.join("signing-p256-public.jwk.json");
    assert_eq!(mode_of(&private_path), 0o600, "private file mode");
    assert_eq!(mode_of(&public_path), 0o644, "public file mode");

    let private_contents = fs::read_to_string(&private_path).expect("read private jwk");
    let public_contents = fs::read_to_string(&public_path).expect("read public jwk");

    let private = PrivateJwk::parse(&private_contents).expect("private JWK parses");
    let public = PublicJwk::parse(&public_contents).expect("public JWK parses");
    let public_value: serde_json::Value =
        serde_json::from_str(&public_contents).expect("public JWK JSON");
    let public_members = public_value
        .as_object()
        .expect("public JWK object")
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        public_members,
        ["alg", "crv", "kid", "kty", "x", "y"].into_iter().collect(),
        "generated service public JWK must have the exact governed shape"
    );

    let expected_kid = public.jkt().expect("thumbprint");
    assert_eq!(private.kty, "EC");
    assert_eq!(private.crv.as_deref(), Some("P-256"));
    assert_eq!(private.alg.as_deref(), Some("ES256"));
    assert_eq!(public.kty, "EC");
    assert_eq!(public.crv.as_deref(), Some("P-256"));
    assert_eq!(public.alg.as_deref(), Some("ES256"));
    assert_eq!(expected_kid.len(), 43);
    assert_eq!(private.kid.as_deref(), Some(expected_kid.as_str()));
    assert_eq!(public.kid.as_deref(), Some(expected_kid.as_str()));
    let message = b"evidencectl generated ES256 key self-test";
    let signature = registry_platform_crypto::sign(message, &private).expect("generated key signs");
    registry_platform_crypto::verify(message, &signature, &public)
        .expect("generated public key verifies");

    // The "d" value must never appear on stdout or stderr.
    let d_value = private.d.clone().expect("private JWK has d");
    assert_output_excludes(&output, &d_value);
}

#[test]
fn signing_rejects_user_supplied_kid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");

    let output = evidencectl()
        .args(["keygen", "signing", "--out-dir"])
        .arg(&out_dir)
        .args(["--kid", "custom-kid-1"])
        .output()
        .expect("run evidencectl");
    assert!(!output.status.success(), "--kid must not be accepted");
    assert!(
        !out_dir.exists(),
        "a rejected invocation must not create keys"
    );
}

#[test]
fn signing_rejects_an_empty_or_whitespace_only_kid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");

    let output = evidencectl()
        .args(["keygen", "signing", "--out-dir"])
        .arg(&out_dir)
        .args(["--kid", "   "])
        .output()
        .expect("run evidencectl");
    assert!(
        !output.status.success(),
        "a whitespace-only --kid must be refused"
    );
    assert!(
        !out_dir.join("signing-p256-private-jwk").exists(),
        "no key material should be generated for a refused --kid"
    );
}

#[test]
fn signing_public_out_overrides_the_default_public_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");
    let public_out = dir.path().join("elsewhere").join("signing-public.json");

    let output = evidencectl()
        .args(["keygen", "signing", "--out-dir"])
        .arg(&out_dir)
        .arg("--public-out")
        .arg(&public_out)
        .output()
        .expect("run evidencectl");
    assert!(output.status.success(), "{}", stderr_of(&output));

    assert!(public_out.is_file());
    assert!(!out_dir.join("signing-p256-public.jwk.json").exists());
    assert_eq!(mode_of(&public_out), 0o644);
}

#[test]
fn holder_writes_private_and_public_jwk_with_holder_filenames() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("holder-keys");

    let output = evidencectl()
        .args(["keygen", "holder", "--out-dir"])
        .arg(&out_dir)
        .output()
        .expect("run evidencectl");
    assert!(output.status.success(), "{}", stderr_of(&output));

    let private_path = out_dir.join("holder-p256-private-jwk");
    let public_path = out_dir.join("holder-p256-public.jwk.json");
    assert_eq!(mode_of(&private_path), 0o600);
    assert_eq!(mode_of(&public_path), 0o644);

    let private_contents = fs::read_to_string(&private_path).expect("read private jwk");
    let public_contents = fs::read_to_string(&public_path).expect("read public jwk");
    let private = PrivateJwk::parse(&private_contents).expect("private JWK parses");
    let public = PublicJwk::parse(&public_contents).expect("public JWK parses");
    assert_eq!(private.kty, "EC");
    assert_eq!(private.crv.as_deref(), Some("P-256"));
    assert_eq!(private.alg.as_deref(), Some("ES256"));
    assert_eq!(private.kid, public.kid);

    let d_value = private.d.clone().expect("private JWK has d");
    assert_output_excludes(&output, &d_value);
}

#[test]
fn secret_writes_exactly_32_raw_bytes_with_owner_only_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("secrets").join("audit-hmac-key");

    let output = evidencectl()
        .args(["keygen", "secret", "--out"])
        .arg(&out)
        .output()
        .expect("run evidencectl");
    assert!(output.status.success(), "{}", stderr_of(&output));

    assert_eq!(mode_of(out.parent().unwrap()), 0o700, "parent dir mode");
    assert_eq!(mode_of(&out), 0o600, "secret file mode");

    let bytes = fs::read(&out).expect("read secret");
    assert_eq!(bytes.len(), 32);
}

#[test]
fn secret_invocations_generate_independent_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = dir.path().join("first.key");
    let second = dir.path().join("second.key");

    for out in [&first, &second] {
        let output = evidencectl()
            .args(["keygen", "secret", "--out"])
            .arg(out)
            .output()
            .expect("run evidencectl");
        assert!(output.status.success(), "{}", stderr_of(&output));
    }

    let first_bytes = fs::read(&first).expect("read first secret");
    let second_bytes = fs::read(&second).expect("read second secret");
    assert_eq!(first_bytes.len(), 32);
    assert_eq!(second_bytes.len(), 32);
    assert_ne!(first_bytes, second_bytes);
}

/// The Evidence runtime rejects any file-provided secret containing a NUL
/// byte, and a uniform 32-byte draw carries one about 11.8% of the time. A
/// generated secret must therefore never contain one, or roughly one project
/// in five fails at `evidence serve` long after `evidence check` passed.
#[test]
fn secret_never_contains_a_nul_byte() {
    let dir = tempfile::tempdir().expect("tempdir");

    // 64 draws leave under one chance in 3000 of a run where every unfixed
    // draw happened to be NUL-free.
    for index in 0..64 {
        let out = dir.path().join(format!("secret-{index}.key"));
        let output = evidencectl()
            .args(["keygen", "secret", "--out"])
            .arg(&out)
            .output()
            .expect("run evidencectl");
        assert!(output.status.success(), "{}", stderr_of(&output));

        let bytes = fs::read(&out).expect("read secret");
        assert_eq!(bytes.len(), 32);
        assert!(
            !bytes.contains(&0),
            "draw {index} contains a NUL byte the runtime rejects"
        );
    }
}

#[test]
fn signing_refuses_overwrite_and_force_option() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");

    let first = evidencectl()
        .args(["keygen", "signing", "--out-dir"])
        .arg(&out_dir)
        .output()
        .expect("run evidencectl");
    assert!(first.status.success(), "{}", stderr_of(&first));

    let private_path = out_dir.join("signing-p256-private-jwk");
    let original_private = fs::read_to_string(&private_path).expect("read private jwk");

    let second = evidencectl()
        .args(["keygen", "signing", "--out-dir"])
        .arg(&out_dir)
        .output()
        .expect("run evidencectl");
    assert!(
        !second.status.success(),
        "second create-only run unexpectedly succeeded"
    );
    let unchanged = fs::read_to_string(&private_path).expect("read private jwk");
    assert_eq!(
        original_private, unchanged,
        "file must be untouched on refusal"
    );

    let force = evidencectl()
        .args(["keygen", "signing", "--out-dir"])
        .arg(&out_dir)
        .arg("--force")
        .output()
        .expect("run evidencectl");
    assert!(!force.status.success(), "--force must not be accepted");
    assert_eq!(
        fs::read_to_string(&private_path).expect("read private jwk"),
        original_private
    );
}

#[test]
fn secret_refuses_overwrite_and_force_option() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("secret.key");

    let first = evidencectl()
        .args(["keygen", "secret", "--out"])
        .arg(&out)
        .output()
        .expect("run evidencectl");
    assert!(first.status.success(), "{}", stderr_of(&first));
    let original = fs::read(&out).expect("read secret");

    let second = evidencectl()
        .args(["keygen", "secret", "--out"])
        .arg(&out)
        .output()
        .expect("run evidencectl");
    assert!(!second.status.success());
    assert_eq!(fs::read(&out).expect("read secret"), original);

    let force = evidencectl()
        .args(["keygen", "secret", "--out"])
        .arg(&out)
        .arg("--force")
        .output()
        .expect("run evidencectl");
    assert!(!force.status.success(), "--force must not be accepted");
    assert_eq!(fs::read(&out).expect("read secret"), original);
}

#[test]
fn signing_batch_abort_leaves_the_private_file_unwritten() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");
    fs::create_dir(&out_dir).expect("create out-dir");

    // Pre-create only the public target; the private target must never be
    // written once the batch is refused.
    fs::write(out_dir.join("signing-p256-public.jwk.json"), b"stale").expect("seed public file");

    let output = evidencectl()
        .args(["keygen", "signing", "--out-dir"])
        .arg(&out_dir)
        .output()
        .expect("run evidencectl");
    assert!(!output.status.success(), "batch should have been refused");
    assert!(
        !out_dir.join("signing-p256-private-jwk").exists(),
        "private key must not be written when the batch aborts"
    );
    let public_contents =
        fs::read(out_dir.join("signing-p256-public.jwk.json")).expect("read public file");
    assert_eq!(
        public_contents, b"stale",
        "pre-existing public file must be untouched"
    );
}

#[test]
fn secret_leaves_a_pre_existing_parent_directorys_mode_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let parent = dir.path().join("secrets");
    fs::create_dir(&parent).expect("create parent dir");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).expect("loosen parent mode");

    let out = parent.join("audit-hmac-key");
    let output = evidencectl()
        .args(["keygen", "secret", "--out"])
        .arg(&out)
        .output()
        .expect("run evidencectl");
    assert!(output.status.success(), "{}", stderr_of(&output));

    assert_eq!(
        mode_of(&parent),
        0o755,
        "a parent directory this invocation did not create must keep its own mode"
    );
}

#[test]
fn signing_out_dir_mode_is_normalized_to_0700_when_pre_created_looser() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");
    fs::create_dir(&out_dir).expect("create out-dir");
    fs::set_permissions(&out_dir, fs::Permissions::from_mode(0o755)).expect("loosen out-dir mode");

    let output = evidencectl()
        .args(["keygen", "signing", "--out-dir"])
        .arg(&out_dir)
        .output()
        .expect("run evidencectl");
    assert!(output.status.success(), "{}", stderr_of(&output));

    assert_eq!(
        mode_of(&out_dir),
        0o700,
        "a pre-existing out-dir must be normalized to owner-only"
    );
}

#[test]
fn signing_refuses_a_symlinked_private_path_without_writing_through_it() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");
    fs::create_dir(&out_dir).expect("create out-dir");

    let target = dir.path().join("attacker-target");
    fs::write(&target, b"untouched").expect("seed symlink target");

    let private_path = out_dir.join("signing-p256-private-jwk");
    symlink(&target, &private_path).expect("create symlink at the private path");

    let output = evidencectl()
        .args(["keygen", "signing", "--out-dir"])
        .arg(&out_dir)
        .output()
        .expect("run evidencectl");
    assert!(
        !output.status.success(),
        "create-only generation must reject a symlink"
    );

    let metadata = fs::symlink_metadata(&private_path).expect("stat private path");
    assert!(
        metadata.file_type().is_symlink(),
        "the symlink must remain untouched"
    );

    let target_contents = fs::read(&target).expect("read symlink target");
    assert_eq!(
        target_contents, b"untouched",
        "the symlink's former target must never be written through"
    );
}

#[test]
fn signing_error_names_the_offending_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");
    fs::create_dir(&out_dir).expect("create out-dir");
    fs::write(out_dir.join("signing-p256-private-jwk"), b"stale").expect("seed private file");

    let output = evidencectl()
        .args(["keygen", "signing", "--out-dir"])
        .arg(&out_dir)
        .output()
        .expect("run evidencectl");
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("signing-p256-private-jwk"),
        "error should name the offending path: {stderr}"
    );
}

/// A bearer token ends up in an HTTP header, where the raw bytes `keygen
/// secret` writes are not valid. `keygen token` must therefore emit only
/// characters a header value accepts, with no trailing newline: the runtime
/// reads the file whole and would carry one into the header.
#[test]
fn token_writes_a_header_safe_value_with_owner_only_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("secrets").join("source-bearer-token");

    let output = evidencectl()
        .args(["keygen", "token", "--out"])
        .arg(&out)
        .output()
        .expect("run evidencectl");
    assert!(output.status.success(), "{}", stderr_of(&output));

    assert_eq!(mode_of(out.parent().unwrap()), 0o700, "parent dir mode");
    assert_eq!(mode_of(&out), 0o600, "token file mode");

    let token = fs::read_to_string(&out).expect("read token");
    assert_eq!(token.len(), 43, "token: {token}");
    assert!(
        token
            .chars()
            .all(|character| character.is_ascii_alphanumeric()
                || character == '-'
                || character == '_'),
        "token carries a character an HTTP header value rejects: {token}"
    );

    // The generated credential is as secret as any private key, and this tool
    // never prints those either.
    assert_output_excludes(&output, &token);
}

#[test]
fn token_invocations_generate_independent_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = dir.path().join("first.token");
    let second = dir.path().join("second.token");

    for out in [&first, &second] {
        let output = evidencectl()
            .args(["keygen", "token", "--out"])
            .arg(out)
            .output()
            .expect("run evidencectl");
        assert!(output.status.success(), "{}", stderr_of(&output));
    }

    assert_ne!(
        fs::read_to_string(&first).expect("read first token"),
        fs::read_to_string(&second).expect("read second token")
    );
}

#[test]
fn token_refuses_overwrite_and_force_option() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("source-bearer-token");
    fs::write(&out, b"already here").expect("seed token");

    let refused = evidencectl()
        .args(["keygen", "token", "--out"])
        .arg(&out)
        .output()
        .expect("run evidencectl");
    assert!(!refused.status.success());
    assert_eq!(
        fs::read_to_string(&out).expect("read token"),
        "already here",
        "a refused run must leave the existing token alone"
    );

    let force = evidencectl()
        .args(["keygen", "token", "--force", "--out"])
        .arg(&out)
        .output()
        .expect("run evidencectl");
    assert!(!force.status.success(), "--force must not be accepted");
    assert_eq!(
        fs::read_to_string(&out).expect("read token"),
        "already here"
    );
}

/// The private JWK a source's `clientAssertionKeyRef` points at. The default
/// covers the common deployment; the file names carry the algorithm so both
/// halves of the SMART on FHIR pair can live in one secret directory.
#[test]
fn client_assertion_defaults_to_es384_with_expected_modes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");

    let output = evidencectl()
        .args(["keygen", "client-assertion", "--out-dir"])
        .arg(&out_dir)
        .output()
        .expect("run evidencectl");
    assert!(
        output.status.success(),
        "keygen client-assertion failed: {}",
        stderr_of(&output)
    );

    assert_eq!(mode_of(&out_dir), 0o700, "out-dir mode");

    let private_path = out_dir.join("client-assertion-p384-private-jwk");
    let public_path = out_dir.join("client-assertion-p384-public.jwk.json");
    assert_eq!(mode_of(&private_path), 0o600, "private file mode");
    assert_eq!(mode_of(&public_path), 0o644, "public file mode");

    let private_contents = fs::read_to_string(&private_path).expect("read private jwk");
    let public_contents = fs::read_to_string(&public_path).expect("read public jwk");
    let private = PrivateJwk::parse(&private_contents).expect("private JWK parses");
    let public = PublicJwk::parse(&public_contents).expect("public JWK parses");

    assert_eq!(
        public_members(&public_contents),
        ["alg", "crv", "kid", "kty", "x", "y"]
    );
    assert_eq!(private.kty, "EC");
    assert_eq!(private.crv.as_deref(), Some("P-384"));
    assert_eq!(private.alg.as_deref(), Some("ES384"));
    assert_eq!(public.alg.as_deref(), Some("ES384"));
    assert_eq!(private.kid, public.kid);
    assert_eq!(
        private.kid.as_deref(),
        Some(public.jkt().expect("thumbprint").as_str())
    );

    // A key the stack cannot sign with is not a key an adopter can deploy.
    let message = b"evidencectl generated ES384 key self-test";
    let signature = registry_platform_crypto::sign(message, &private).expect("generated key signs");
    registry_platform_crypto::verify(message, &signature, &public)
        .expect("generated public key verifies");

    assert_output_excludes(&output, &private.d.clone().expect("private JWK has d"));
}

/// An authorization server conforming to SMART App Launch v2.2.0 has to
/// validate only one of RS384 and ES384, so the RSA half of the pair has to be
/// reachable too.
#[test]
fn client_assertion_rs384_writes_an_rsa_key_under_its_own_filenames() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");

    let output = evidencectl()
        .args([
            "keygen",
            "client-assertion",
            "--algorithm",
            "rs384",
            "--out-dir",
        ])
        .arg(&out_dir)
        .output()
        .expect("run evidencectl");
    assert!(output.status.success(), "{}", stderr_of(&output));

    let private_path = out_dir.join("client-assertion-rsa2048-private-jwk");
    let public_path = out_dir.join("client-assertion-rsa2048-public.jwk.json");
    assert_eq!(mode_of(&private_path), 0o600, "private file mode");
    assert_eq!(mode_of(&public_path), 0o644, "public file mode");
    assert!(
        !out_dir.join("client-assertion-p384-private-jwk").exists(),
        "the ES384 filenames belong to the ES384 key alone"
    );

    let private_contents = fs::read_to_string(&private_path).expect("read private jwk");
    let public_contents = fs::read_to_string(&public_path).expect("read public jwk");
    let private = PrivateJwk::parse(&private_contents).expect("private JWK parses");
    let public = PublicJwk::parse(&public_contents).expect("public JWK parses");

    assert_eq!(
        public_members(&public_contents),
        ["alg", "e", "kid", "kty", "n"]
    );
    assert_eq!(private.kty, "RSA");
    assert_eq!(private.alg.as_deref(), Some("RS384"));
    assert_eq!(private.crv, None);
    assert_eq!(private.kid, public.kid);

    let message = b"evidencectl generated RS384 key self-test";
    let signature = registry_platform_crypto::sign(message, &private).expect("generated key signs");
    registry_platform_crypto::verify(message, &signature, &public)
        .expect("generated public key verifies");

    // An RSA key has seven secret members beside `d`, and none of them may
    // reach the terminal either.
    for member in [
        private.d.as_deref(),
        private.p.as_deref(),
        private.q.as_deref(),
        private.dp.as_deref(),
        private.dq.as_deref(),
        private.qi.as_deref(),
    ] {
        assert_output_excludes(
            &output,
            member.expect("private JWK carries every RSA member"),
        );
    }
}

#[test]
fn client_assertion_rejects_an_unknown_algorithm() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");

    let output = evidencectl()
        .args([
            "keygen",
            "client-assertion",
            "--algorithm",
            "es256",
            "--out-dir",
        ])
        .arg(&out_dir)
        .output()
        .expect("run evidencectl");
    assert!(
        !output.status.success(),
        "an algorithm outside the SMART pair must not be accepted"
    );
    assert!(
        !out_dir.exists(),
        "a rejected invocation must not create keys"
    );
}

#[test]
fn client_assertion_public_out_overrides_the_default_public_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");
    let public_out = dir.path().join("elsewhere").join("client-public.json");

    let output = evidencectl()
        .args(["keygen", "client-assertion", "--out-dir"])
        .arg(&out_dir)
        .arg("--public-out")
        .arg(&public_out)
        .output()
        .expect("run evidencectl");
    assert!(output.status.success(), "{}", stderr_of(&output));

    assert!(public_out.is_file());
    assert!(!out_dir
        .join("client-assertion-p384-public.jwk.json")
        .exists());
    assert_eq!(mode_of(&public_out), 0o644);
}

/// One assertion key per authorization server is what the operator contract
/// asks for, and Evidence resolves every `secret:file/` reference inside one
/// flat secret root. Two keys therefore have to be nameable in the same
/// directory: with only the algorithm deciding the filename, the second
/// invocation collides with the first and the guidance cannot be followed
/// without moving files by hand.
#[test]
fn client_assertion_names_a_second_key_in_the_same_secret_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");

    for name in ["records-authority-key", "registry-authority-key"] {
        let output = evidencectl()
            .args(["keygen", "client-assertion", "--out-dir"])
            .arg(&out_dir)
            .args(["--private-name", name])
            .output()
            .expect("run evidencectl");
        assert!(
            output.status.success(),
            "keygen client-assertion --private-name {name} failed: {}",
            stderr_of(&output)
        );
    }

    // The name the operator states is the name the bundle references, so it is
    // the private file's own name and carries no algorithm or suffix. The
    // public half follows it, since a second pair needs a second public path
    // just as much.
    let first = out_dir.join("records-authority-key");
    let second = out_dir.join("registry-authority-key");
    assert_eq!(mode_of(&first), 0o600, "private file mode");
    assert_eq!(mode_of(&second), 0o600, "private file mode");
    assert_eq!(
        mode_of(&out_dir.join("records-authority-key-public.jwk.json")),
        0o644
    );
    assert_eq!(
        mode_of(&out_dir.join("registry-authority-key-public.jwk.json")),
        0o644
    );
    assert!(
        !out_dir.join("client-assertion-p384-private-jwk").exists(),
        "a stated name must replace the algorithm default, not add to it"
    );

    // Distinct keys, not one key written twice: a server told to expect one
    // public half must not accept assertions minted for the other.
    let first_key = PrivateJwk::parse(&fs::read_to_string(&first).expect("read private jwk"))
        .expect("private JWK parses");
    let second_key = PrivateJwk::parse(&fs::read_to_string(&second).expect("read private jwk"))
        .expect("private JWK parses");
    assert_ne!(first_key.kid, second_key.kid, "both servers got one key");
}

/// A name outside the resolver's `secret:file/` grammar produces a key no
/// bundle can point at, and one containing a path separator or a parent segment
/// would leave the secret directory entirely. Both are refused before anything
/// is written, so the operator learns at generation rather than at load.
#[test]
fn client_assertion_refuses_a_private_name_no_bundle_could_reference() {
    for name in [
        "../escape",
        "nested/name",
        "Upper",
        ".hidden",
        "9-leading-digit",
        "",
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let out_dir = dir.path().join("keys");
        let output = evidencectl()
            .args(["keygen", "client-assertion", "--out-dir"])
            .arg(&out_dir)
            .args(["--private-name", name])
            .output()
            .expect("run evidencectl");
        assert!(
            !output.status.success(),
            "--private-name {name:?} was accepted"
        );
        assert!(
            !out_dir.exists(),
            "--private-name {name:?} was refused after writing"
        );
    }
}

#[test]
fn client_assertion_refuses_overwrite_and_force_option() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_dir = dir.path().join("keys");

    let first = evidencectl()
        .args(["keygen", "client-assertion", "--out-dir"])
        .arg(&out_dir)
        .output()
        .expect("run evidencectl");
    assert!(first.status.success(), "{}", stderr_of(&first));

    let private_path = out_dir.join("client-assertion-p384-private-jwk");
    let original_private = fs::read_to_string(&private_path).expect("read private jwk");

    let second = evidencectl()
        .args(["keygen", "client-assertion", "--out-dir"])
        .arg(&out_dir)
        .output()
        .expect("run evidencectl");
    assert!(
        !second.status.success(),
        "second create-only run unexpectedly succeeded"
    );
    assert_eq!(
        fs::read_to_string(&private_path).expect("read private jwk"),
        original_private,
        "file must be untouched on refusal"
    );

    let force = evidencectl()
        .args(["keygen", "client-assertion", "--out-dir"])
        .arg(&out_dir)
        .arg("--force")
        .output()
        .expect("run evidencectl");
    assert!(!force.status.success(), "--force must not be accepted");
    assert_eq!(
        fs::read_to_string(&private_path).expect("read private jwk"),
        original_private
    );
}

#[test]
fn client_assertion_invocations_generate_independent_keys() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut kids = Vec::new();

    for index in 0..2 {
        let out_dir = dir.path().join(format!("keys-{index}"));
        let output = evidencectl()
            .args(["keygen", "client-assertion", "--out-dir"])
            .arg(&out_dir)
            .output()
            .expect("run evidencectl");
        assert!(output.status.success(), "{}", stderr_of(&output));

        let contents = fs::read_to_string(out_dir.join("client-assertion-p384-private-jwk"))
            .expect("read private jwk");
        kids.push(
            PrivateJwk::parse(&contents)
                .expect("private JWK parses")
                .d
                .clone(),
        );
    }

    assert_ne!(kids[0], kids[1], "two runs must not share a private scalar");
}

/// The exact member set of a public JWK file, sorted, so a stray member is a
/// failure rather than something an adopter publishes by accident.
fn public_members(contents: &str) -> Vec<String> {
    let value: serde_json::Value = serde_json::from_str(contents).expect("public JWK JSON");
    let mut members = value
        .as_object()
        .expect("public JWK object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    members.sort();
    members
}

/// `keygen secret` is the obvious tool for the one secret every scaffolded
/// bundle needs, and it is the wrong one. Its own help has to say so, because
/// the alternative is discovering it at the first live request.
#[test]
fn secret_help_says_it_does_not_make_bearer_tokens() {
    let output = evidencectl()
        .args(["keygen", "secret", "--help"])
        .output()
        .expect("run evidencectl");
    assert!(output.status.success(), "{}", stderr_of(&output));

    let help = stdout_of(&output);
    assert!(
        help.contains("keygen token"),
        "keygen secret's help never points at the token generator:\n{help}"
    );
}
