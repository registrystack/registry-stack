// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn config_verify_bundle_cli_accepts_bundle_flags() {
    let args = Args::try_parse_from([
        "registry-notary",
        "config",
        "verify-bundle",
        "--bundle-dir",
        "/etc/registry-notary/bundle",
        "--anchor-path",
        "/etc/registry-notary/trust_anchor.json",
        "--state-path",
        "/var/lib/registry-notary/config-state/antirollback.json",
    ])
    .expect("args parse");

    let Some(Command::Config {
        command: ConfigCommand::VerifyBundle(command),
    }) = args.command
    else {
        panic!("expected config verify-bundle command");
    };
    assert_eq!(
        command.bundle_dir,
        PathBuf::from("/etc/registry-notary/bundle")
    );
    assert_eq!(
        command.anchor_path,
        PathBuf::from("/etc/registry-notary/trust_anchor.json")
    );
    assert_eq!(
        command.state_path,
        PathBuf::from("/var/lib/registry-notary/config-state/antirollback.json")
    );
}

#[test]
fn config_verify_bundle_cli_requires_state_path() {
    let err = Args::try_parse_from([
        "registry-notary",
        "config",
        "verify-bundle",
        "--bundle-dir",
        "/etc/registry-notary/bundle",
        "--anchor-path",
        "/etc/registry-notary/trust_anchor.json",
    ])
    .expect_err("missing state-path is rejected");

    assert!(err.to_string().contains("--state-path"));
}

#[test]
fn config_apply_bundle_cli_is_removed() {
    let err = Args::try_parse_from(["registry-notary", "config", "apply-bundle"])
        .expect_err("apply-bundle is no longer a supported config subcommand");

    assert!(
        err.to_string().contains("unrecognized subcommand"),
        "unexpected error: {err}"
    );
}
