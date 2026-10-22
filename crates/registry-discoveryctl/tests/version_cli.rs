use std::process::Command;

fn version_output(flag: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_discoveryctl"))
        .arg(flag)
        .output()
        .unwrap_or_else(|err| panic!("discoveryctl {flag} runs: {err}"));

    assert!(
        output.status.success(),
        "discoveryctl {flag} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn version_output_uses_the_product_build_identity() {
    for flag in ["--version", "-V"] {
        assert_eq!(
            version_output(flag),
            format!(
                "discoveryctl {}\n",
                registry_discoveryctl::build_info::DISPLAY_VERSION
            )
        );
    }
}

#[test]
fn an_unmarked_build_is_visibly_a_development_build() {
    if !registry_discoveryctl::build_info::IS_RELEASE_BUILD
        && !registry_discoveryctl::build_info::IS_NIGHTLY_BUILD
    {
        assert_eq!(
            version_output("--version"),
            format!("discoveryctl {}-dev\n", env!("CARGO_PKG_VERSION"))
        );
    }
}
