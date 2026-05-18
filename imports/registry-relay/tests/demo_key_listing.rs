// SPDX-License-Identifier: Apache-2.0
//! Focused checks for the demo key chooser command.

use std::process::Command;

fn run_key_listing(config: &str, env_file: Option<&std::path::Path>) -> String {
    let root = env!("CARGO_MANIFEST_DIR");
    let python = std::env::var("PYTHON").unwrap_or_else(|_| "python3".to_string());
    let mut command = Command::new(python);
    command
        .current_dir(root)
        .arg("demo/scripts/list_demo_keys.py")
        .arg("--config")
        .arg(config);
    if let Some(env_file) = env_file {
        command.arg("--env-file").arg(env_file);
    }
    let output = command.output().expect("demo key listing command runs");

    assert!(
        output.status.success(),
        "demo key listing failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout is utf-8")
}

#[test]
fn demo_key_listing_uses_openapi_words_and_generated_raw_keys() {
    let env_path = std::env::temp_dir().join(format!(
        "registry-relay-demo-keys-{}.env",
        std::process::id()
    ));
    std::fs::write(
        &env_path,
        [
            "export CATALOG_VIEWER_RAW='raw-catalog-token'",
            "export CASEWORK_SYSTEM_RAW='raw-casework-token'",
            "export VERIFICATION_SERVICE_RAW='raw-verify-token'",
        ]
        .join("\n"),
    )
    .expect("write fixture env file");

    let all_demos = run_key_listing("demo/config/all_demos.yaml", Some(&env_path));

    for expected in [
        "metadataKey",
        "raw-casework-token",
        "List datasets",
        "Run aggregate",
        "Get record",
        "Verify record exists",
    ] {
        assert!(
            all_demos.contains(expected),
            "all_demos key listing should contain {expected:?}:\n{all_demos}"
        );
    }

    assert!(
        !all_demos.contains("sha256:"),
        "key listing must not print stored fingerprints"
    );
    assert!(
        !all_demos.contains("Scope coverage:"),
        "default key listing should stay compact:\n{all_demos}"
    );

    let disability = run_key_listing("demo/config/disability_registry.yaml", Some(&env_path));
    assert!(
        disability.contains("Create claim verification"),
        "disability key listing should expose submitted-claim wording:\n{disability}"
    );

    std::fs::remove_file(env_path).expect("remove fixture env file");
}
