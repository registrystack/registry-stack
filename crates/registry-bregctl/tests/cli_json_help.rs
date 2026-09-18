//! `bregctl help --format json` publishes the machine-readable command tree
//! with the same schema the offline CLI reference catalog uses.

use std::process::ExitCode;

#[test]
fn help_honours_the_global_json_format_with_the_catalog_schema() {
    for arguments in [
        vec!["bregctl", "--format", "json", "help"],
        vec!["bregctl", "help", "--format", "json"],
        vec!["bregctl", "--format", "json", "--help"],
        vec!["bregctl", "--format", "json", "project", "--help"],
    ] {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = registry_bregctl::run_from(arguments.clone(), &mut stdout, &mut stderr);
        assert_eq!(status, ExitCode::SUCCESS, "arguments: {arguments:?}");
        assert!(
            stderr.is_empty(),
            "JSON help wrote stderr for {arguments:?}"
        );
        let rendered = String::from_utf8(stdout).expect("catalog is UTF-8");
        let catalog: serde_json::Value = serde_json::from_str(rendered.trim())
            .unwrap_or_else(|error| panic!("invalid catalog for {arguments:?}: {error}"));
        assert_eq!(
            catalog["schema_version"], "registry.cli-reference/v2",
            "arguments: {arguments:?}"
        );
        let binaries = catalog["binaries"].as_array().expect("binaries array");
        assert_eq!(binaries.len(), 1, "arguments: {arguments:?}");
        assert_eq!(binaries[0]["name"], "bregctl");
        // The published catalog states the symbolic-link refusal on every
        // bregctl path argument; the inline catalog is the same walker and
        // must not drift from it.
        assert!(
            rendered.contains("A symbolic link at any component of this path is refused."),
            "arguments: {arguments:?}"
        );
    }
}

/// A `help`-spelled positional value is not the subcommand token, so it must
/// reach the command instead of being mistaken for `--format json help`.
#[test]
fn a_help_spelled_value_is_not_mistaken_for_the_help_catalog() {
    let arguments = vec!["bregctl", "--format", "json", "explain", "access", "help"];
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = registry_bregctl::run_from(arguments.clone(), &mut stdout, &mut stderr);
    assert_ne!(
        status,
        ExitCode::SUCCESS,
        "a project directory named `help` does not exist, so this must not succeed"
    );
    let rendered = String::from_utf8(stdout).expect("output is UTF-8");
    assert!(
        !rendered.contains("schema_version"),
        "the `help` value hijacked the command into printing the CLI reference catalog: {rendered}"
    );
}
