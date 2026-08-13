//! Process-boundary contract for owner-only client-secret provisioning.

use std::{fs, os::unix::fs::PermissionsExt as _, process::Command};

use registry_platform_authcommon::verify_api_key;

#[test]
fn generation_prints_only_the_fingerprint_and_never_replaces_the_secret() {
    let directory = tempfile::tempdir().expect("temp dir");
    let secret_path = directory.path().join("qgis-client-secret");

    let first = Command::new(env!("CARGO_BIN_EXE_mint"))
        .args(["client-secret", "generate", "--out"])
        .arg(&secret_path)
        .output()
        .expect("the Mint binary runs");
    assert!(
        first.status.success(),
        "generation failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let fingerprint = String::from_utf8(first.stdout)
        .expect("fingerprint is UTF-8")
        .trim()
        .to_owned();
    let secret = fs::read_to_string(&secret_path).expect("secret reads");
    let secret = secret.trim_end();
    assert_eq!(verify_api_key(secret, &fingerprint), Ok(true));
    assert!(!fingerprint.contains(secret));
    assert_eq!(
        fs::metadata(&secret_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let second = Command::new(env!("CARGO_BIN_EXE_mint"))
        .args(["client-secret", "generate", "--out"])
        .arg(&secret_path)
        .output()
        .expect("the Mint binary runs again");
    assert!(!second.status.success());
    assert!(
        second.stdout.is_empty(),
        "a refusal printed credential output"
    );
    assert_eq!(
        fs::read_to_string(secret_path).expect("original secret remains"),
        format!("{secret}\n")
    );
}
