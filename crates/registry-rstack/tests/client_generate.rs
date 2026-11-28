// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::process::{Command, Output};

fn generate(node: bool, generator: bool, help: bool) -> Output {
    let project = tempfile::tempdir().unwrap();
    let bin = project.path().join("application/node_modules/.bin");
    fs::create_dir_all(&bin).unwrap();
    if node {
        fs::copy("/bin/sh", bin.join("node")).unwrap();
    }
    if generator {
        fs::write(
            bin.join("registry-generate"),
            "printf '%s\n' \"$RSTACK_BREGCTL_BIN\" \"$@\"; exit 7",
        )
        .unwrap();
    }
    let bregctl = bin.join("bregctl");
    fs::write(&bregctl, "").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rstack"));
    command
        .current_dir(project.path())
        .env("PATH", &bin)
        .env("RSTACK_BREGCTL_BIN", &bregctl)
        .args(["--install-root", "install", "client", "generate"]);
    if help {
        command.arg("--help");
    } else {
        command.args([
            "--register",
            "first=register one",
            "--register",
            "second=register-two",
            "--author-profile",
            "first=writer",
            "--route-prefix",
            "first=/first",
            "--products",
            "documents,casework",
            "--output",
            "application/src/generated/service.ts",
        ]);
    }
    command.output().unwrap()
}

#[test]
fn forwards_to_the_local_generator_from_a_nested_output_path() {
    let output = generate(true, true, false);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout
        .lines()
        .next()
        .unwrap()
        .ends_with("/node_modules/.bin/bregctl"));
    assert_eq!(
        stdout.lines().skip(1).collect::<Vec<_>>(),
        [
            "--register",
            "first=register one",
            "--register",
            "second=register-two",
            "--author-profile",
            "first=writer",
            "--route-prefix",
            "first=/first",
            "--products",
            "documents,casework",
            "--output",
            "application/src/generated/service.ts",
        ]
    );
}

#[test]
fn names_each_missing_prerequisite_and_the_install_command() {
    for (node, generator, code) in [
        (false, true, "rstack.client.node-missing"),
        (true, false, "rstack.client.generator-missing"),
    ] {
        let output = generate(node, generator, false);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(code), "{stderr}");
        assert!(
            stderr.contains("npm install @registrystack/client in the application project"),
            "{stderr}"
        );
    }
}

#[test]
fn help_works_without_node_or_the_generator() {
    let output = generate(false, false, true);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    for option in [
        "--register",
        "--author-profile",
        "--route-prefix",
        "--products",
        "--output",
    ] {
        assert!(stdout.contains(option), "{stdout}");
    }
}
