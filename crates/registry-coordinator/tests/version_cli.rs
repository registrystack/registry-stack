// SPDX-License-Identifier: Apache-2.0
use std::process::Command;

fn version_output(executable: &str, flag: &str) -> String {
    let output = Command::new(executable)
        .arg(flag)
        .output()
        .unwrap_or_else(|err| panic!("{executable} {flag} runs: {err}"));
    assert!(
        output.status.success(),
        "{executable} {flag} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Both Coordinator executables report the version text the shared build
/// identity decides, so a nightly build names its dated source identity and
/// an unmarked build names a development version. The release scripts compare
/// `--version` against that text before they stage a binary.
#[test]
fn both_executables_report_the_shared_build_identity() {
    for (name, executable) in [
        ("coordinator", env!("CARGO_BIN_EXE_coordinator")),
        ("coordinatorctl", env!("CARGO_BIN_EXE_coordinatorctl")),
    ] {
        for flag in ["--version", "-V"] {
            assert_eq!(
                version_output(executable, flag),
                format!("{name} {}\n", registry_platform_buildinfo::DISPLAY_VERSION)
            );
        }
    }
}

#[test]
fn version_output_distinguishes_the_build_identity() {
    let expected = if registry_platform_buildinfo::IS_RELEASE_BUILD {
        env!("CARGO_PKG_VERSION").to_owned()
    } else if registry_platform_buildinfo::IS_NIGHTLY_BUILD {
        registry_platform_buildinfo::DISPLAY_VERSION.to_owned()
    } else {
        format!("{}-dev", env!("CARGO_PKG_VERSION"))
    };
    assert_eq!(
        version_output(env!("CARGO_BIN_EXE_coordinator"), "--version"),
        format!("coordinator {expected}\n")
    );
}
