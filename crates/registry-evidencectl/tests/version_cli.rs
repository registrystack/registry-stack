use std::process::Command;

fn version_output(flag: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .arg(flag)
        .output()
        .unwrap_or_else(|err| panic!("evidencectl {flag} runs: {err}"));

    assert!(
        output.status.success(),
        "evidencectl {flag} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn version_output_uses_user_facing_command_name() {
    for flag in ["--version", "-V"] {
        assert_eq!(
            version_output(flag),
            format!(
                "evidencectl {}\n",
                registry_platform_buildinfo::DISPLAY_VERSION
            )
        );
    }
}

#[test]
fn version_output_distinguishes_the_build_identity() {
    let expected = if registry_platform_buildinfo::IS_RELEASE_BUILD {
        env!("CARGO_PKG_VERSION").to_owned()
    } else if registry_platform_buildinfo::IS_NIGHTLY_BUILD {
        option_env!("REGISTRY_NIGHTLY_TAG")
            .expect("nightly build marker")
            .strip_prefix('v')
            .expect("nightly tag starts with v")
            .to_owned()
    } else {
        format!("{}-dev", env!("CARGO_PKG_VERSION"))
    };

    assert_eq!(
        version_output("--version"),
        format!("evidencectl {expected}\n")
    );
}
