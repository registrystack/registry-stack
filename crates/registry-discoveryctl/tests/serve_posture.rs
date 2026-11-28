// SPDX-License-Identifier: Apache-2.0
#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn serve_forwards_the_resolved_posture() {
    let root = tempfile::tempdir().unwrap();
    let service = root.path().join("discovery");
    let runtime = root.path().join("runtime.yaml");
    fs::write(&service, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
    fs::set_permissions(&service, fs::Permissions::from_mode(0o700)).unwrap();

    for (environment, flag, expected) in [
        (None, None, "production"),
        (Some("development"), None, "development"),
        (None, Some("development"), "development"),
        (Some("production"), Some("production"), "production"),
    ] {
        let mut ctl = Command::new(env!("CARGO_BIN_EXE_discoveryctl"));
        ctl.args(["serve", "--discovery-bin"])
            .arg(&service)
            .arg("--runtime-config")
            .arg(&runtime)
            .env_remove("REGISTRY_STACK_POSTURE");
        if let Some(value) = environment {
            ctl.env("REGISTRY_STACK_POSTURE", value);
        }
        if let Some(value) = flag {
            ctl.args(["--posture", value]);
        }
        let output = ctl.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!(
                "--runtime-config\n{}\n--posture\n{expected}\n",
                runtime.display()
            )
        );
    }
}
