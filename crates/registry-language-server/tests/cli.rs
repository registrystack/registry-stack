// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn standalone_binary_reports_its_version_and_usage() {
    let binary = env!("CARGO_BIN_EXE_registry-language-server");
    let version = Command::new(binary).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap(),
        format!("registry-language-server {}\n", env!("CARGO_PKG_VERSION"))
    );

    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8(help.stdout)
        .unwrap()
        .contains("registry-language-server [--workspace-analysis|--version|--help]"));
}
