use std::{fs, path::Path, process::Command};

use serde_json::Value;
use sha2::{Digest as _, Sha256};

fn assert_json_format_refusal(arguments: &[&str], expected_command: &str) {
    let directory = tempfile::tempdir().expect("temporary working directory");
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .current_dir(directory.path())
        .output()
        .expect("run evidencectl");

    assert_eq!(output.status.code(), Some(2), "arguments: {arguments:?}");
    assert!(
        output.stderr.is_empty(),
        "JSON mode wrote human diagnostics for {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("invalid JSON for {arguments:?}: {error}"));
    assert_eq!(report["status"], "usage-error");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "evidencectl.format.unsupported"
    );
    assert_eq!(report["diagnostics"][0]["artifact"], expected_command);
    assert_eq!(report["diagnostics"][0]["path"], "$.format");
}

/// Every command that renders only human prose, with arguments that parse.
const HUMAN_ONLY_COMMANDS: &[(&str, &[&str])] = &[
    ("target new", &["target", "new", "target", "--local"]),
    ("source mock generate", &["source", "mock", "generate"]),
    ("source mock check", &["source", "mock", "check"]),
    ("source mock serve", &["source", "mock", "serve"]),
    ("source detach", &["source", "detach", "records"]),
    (
        "request prepare",
        &["request", "prepare", "question", "--name", "request"],
    ),
    (
        "request verify",
        &[
            "request",
            "verify",
            "response.jwt",
            "--context",
            "verification.json",
            "--output",
            "verified.json",
        ],
    ),
    (
        "verify",
        &[
            "verify",
            "response.jwt",
            "--context",
            "verification.json",
            "--output",
            "verified.json",
        ],
    ),
    (
        "client profile create",
        &[
            "client",
            "profile",
            "create",
            "--base-url",
            "https://evidence.example",
            "--client-id",
            "client",
            "--output",
            "client.json",
            "--private-key-file",
            "client.jwk",
        ],
    ),
    (
        "client contracts fetch",
        &[
            "client",
            "contracts",
            "fetch",
            "--profile",
            "client.json",
            "--output",
            "contracts.json",
        ],
    ),
    ("tooling language-server", &["tooling", "language-server"]),
    (
        "__dev-supervisor",
        &[
            "__dev-supervisor",
            "--dev-root",
            "dev",
            "--evidence-bin",
            "evidence",
            "--docker-bin",
            "docker",
            "--ready-timeout-seconds",
            "1",
        ],
    ),
];

#[test]
fn global_json_refuses_every_legacy_human_renderer_before_dispatch() {
    for (command, arguments) in HUMAN_ONLY_COMMANDS {
        assert_json_format_refusal(&[&["--format", "json"], *arguments].concat(), command);
    }
}

#[test]
fn a_json_format_after_a_human_only_command_is_the_same_refusal() {
    for (command, arguments) in HUMAN_ONLY_COMMANDS {
        assert_json_format_refusal(&[*arguments, &["--format", "json"]].concat(), command);
        assert_json_format_refusal(&[*arguments, &["--format=json"]].concat(), command);
    }
}

/// A human-only command's help advertises only the output it renders.
#[test]
fn human_only_command_help_offers_only_human_output() {
    for (command, _) in HUMAN_ONLY_COMMANDS {
        let path: Vec<&str> = command.split(' ').collect();
        let help = help_text(&[path.as_slice(), &["--help"]].concat());
        assert!(
            help.contains("[possible values: human]"),
            "{command} help does not offer human output alone: {help}"
        );
        assert!(
            !help.contains("json]"),
            "{command} help offers JSON: {help}"
        );
    }
    let help = help_text(&["source", "suggest", "--help"]);
    assert!(
        help.contains("[possible values: human, json]"),
        "a migrated command lost its JSON output: {help}"
    );
}

fn help_text(arguments: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .output()
        .expect("run evidencectl");
    assert!(output.status.success(), "arguments: {arguments:?}");
    String::from_utf8(output.stdout).expect("help is UTF-8")
}

/// The commands whose JSON reports this crate migrated answer the shared
/// success envelope — one JSON object on stdout — and, when their inputs are
/// missing, fail with the standard JSON failure document instead of the
/// `evidencectl.format.unsupported` refusal or human prose.
#[test]
fn migrated_json_commands_answer_one_json_document() {
    let cases: &[&[&str]] = &[
        &[
            "access",
            "policy",
            "add",
            "policy",
            "--question",
            "question",
        ],
        &["access", "policy", "list"],
        &[
            "access",
            "client",
            "add",
            "client",
            "--policy",
            "policy",
            "--generate-local-key",
        ],
        &["access", "client", "list"],
        &["access", "client", "revoke", "client"],
        &["keygen", "secret", "--output", "secret"],
        &["jwks", "--output", "jwks.json", "public.jwk"],
        &["source", "suggest", "--openapi", "source.openapi.yaml"],
    ];
    let directory = tempfile::tempdir().expect("temporary working directory");
    for arguments in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args(["--format", "json"])
            .args(*arguments)
            .current_dir(directory.path())
            .output()
            .expect("run evidencectl");
        assert_ne!(output.status.code(), Some(2), "arguments: {arguments:?}");
        assert!(
            output.stderr.is_empty(),
            "JSON mode wrote human diagnostics for {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("invalid JSON for {arguments:?}: {error}"));
        if output.status.success() {
            for key in ["command", "ok", "status"] {
                assert!(report.get(key).is_some(), "{arguments:?} lacks {key}");
            }
            assert_eq!(report["ok"], Value::Bool(true), "arguments: {arguments:?}");
            assert_eq!(report["status"], "complete", "arguments: {arguments:?}");
        } else {
            assert!(
                report["diagnostics"][0]["code"]
                    .as_str()
                    .is_some_and(|code| code != "evidencectl.format.unsupported"),
                "{arguments:?} is still refused: {report}"
            );
        }
    }
}

/// A `help`-spelled positional value is not the subcommand token, so it must
/// reach the command instead of being mistaken for `--format json help`.
#[test]
fn a_help_spelled_value_is_not_mistaken_for_the_help_catalog() {
    let directory = tempfile::tempdir().expect("temporary working directory");
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args([
            "--format",
            "json",
            "access",
            "client",
            "revoke",
            "help",
            "--project",
        ])
        .arg(directory.path())
        .output()
        .expect("run evidencectl");

    assert_ne!(
        output.status.code(),
        Some(0),
        "a client named `help` cannot be revoked in an empty project, so this must not succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("schema_version"),
        "the `help` value hijacked the command into printing the CLI reference catalog: {stdout}"
    );
}

#[test]
fn source_comparison_failures_emit_exactly_one_json_document() {
    for command in ["diff", "import", "update"] {
        let directory = tempfile::tempdir().expect("temporary working directory");
        let project = directory.path().join("project");
        fs::create_dir(&project).expect("project directory");
        fs::write(
            project.join("evidence-project.yaml"),
            registry_evidence_authoring::default_project_marker_document(),
        )
        .expect("project marker");
        let export = malformed_source_export(directory.path());

        let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args(["--format", "json", "source", command])
            .arg(&export)
            .arg("--project")
            .arg(&project)
            .output()
            .expect("run evidencectl source comparison");

        assert_eq!(output.status.code(), Some(1), "source {command}");
        assert!(
            output.stderr.is_empty(),
            "source {command} wrote prose to stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!("source {command} did not emit one JSON document: {error}")
        });
        assert_eq!(report["status"], "domain-refusal");
        assert_eq!(
            report["diagnostics"][0]["code"],
            "evidencectl.domain-refusal"
        );
        assert!(!project.join("sources/lookup.yaml").exists());
        assert!(!project.join(".evidence/source-imports/state.json").exists());
    }
}

fn malformed_source_export(root: &Path) -> std::path::PathBuf {
    const SOURCE: &str = "transport: http-json\nconnection: remote\nrequest:\n  selectorInputs:\n    - role: subject\n      alternatives: [{profile: record-code, fields: [code]}]\n  prepareScript: adapters/lookup-prepare.rhai\n  adapterParametersSchema: schemas/lookup-parameters.yaml\nresponseSchema: schemas/lookup-response.yaml\nfactSchema: schemas/lookup-facts.yaml\nextractScript: adapters/lookup-extract.rhai\n";
    let export = root.join("export");
    let artifacts = [
        ("sources/lookup.yaml", SOURCE),
        (
            "selectors/record-code.yaml",
            "fields: {code: {type: string, minimumBytes: 1, maximumBytes: 128}}\n",
        ),
        (
            "schemas/lookup-parameters.yaml",
            "type: object\nproperties: {}\nadditionalProperties: false\n",
        ),
        (
            "schemas/lookup-response.yaml",
            "type: object\nproperties: {}\nadditionalProperties: false\n",
        ),
        (
            "schemas/lookup-facts.yaml",
            "type: object\nproperties: {}\nadditionalProperties: false\n",
        ),
        (
            "adapters/lookup-prepare.rhai",
            "fn prepare(selectors, context) { #{query: [], body: ()} }\n",
        ),
        ("adapters/lookup-extract.rhai", "fn extract( { incomplete\n"),
    ];
    for (path, contents) in artifacts {
        let path = export.join(path);
        fs::create_dir_all(path.parent().expect("artifact parent")).expect("artifact directory");
        fs::write(path, contents).expect("source artifact");
    }
    let manifest = serde_json::json!({
        "formatVersion": 1,
        "sourceId": "lookup",
        "provenance": {"producer": "output-format-test", "revision": "malformed"},
        "artifacts": artifacts.map(|(path, contents)| serde_json::json!({
            "path": path,
            "sha256": hex::encode(Sha256::digest(contents.as_bytes())),
        })),
    });
    fs::write(
        export.join("source-export.json"),
        serde_json::to_vec(&manifest).expect("source manifest JSON"),
    )
    .expect("source manifest");
    export
}

/// The legacy `--json` flags are exact aliases for `--format json`: a failure
/// answers the same one JSON document on stdout, never human prose on stderr.
#[test]
fn legacy_json_flags_fail_with_one_json_document() {
    let cases: &[&[&str]] = &[
        &["target", "explain", "missing", "--json"],
        &["fixtures", "run", "--project", "missing", "--json"],
        &["doctor", "--project", "missing", "--json"],
    ];
    let directory = tempfile::tempdir().expect("temporary working directory");
    for arguments in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args(*arguments)
            .current_dir(directory.path())
            .output()
            .expect("run evidencectl");
        assert!(!output.status.success(), "arguments: {arguments:?}");
        assert!(
            output.stderr.is_empty(),
            "--json wrote human diagnostics for {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("invalid JSON for {arguments:?}: {error}"));
        assert!(
            report["diagnostics"][0]["code"].is_string(),
            "{arguments:?} answered no diagnostic: {report}"
        );
    }
}

/// A command line that does not parse still honors a legacy `--json` flag
/// named after its command, so the usage error is one JSON document too.
#[test]
fn legacy_json_flags_render_usage_errors_as_json() {
    let cases: &[&[&str]] = &[
        &["target", "explain", "--json", "--bogus"],
        &["fixtures", "run", "--json", "--bogus"],
        &["doctor", "--json", "--bogus"],
    ];
    let directory = tempfile::tempdir().expect("temporary working directory");
    for arguments in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
            .args(*arguments)
            .current_dir(directory.path())
            .output()
            .expect("run evidencectl");
        assert_eq!(output.status.code(), Some(2), "arguments: {arguments:?}");
        assert!(
            output.stderr.is_empty(),
            "--json wrote human diagnostics for {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("invalid JSON for {arguments:?}: {error}"));
        assert_eq!(report["status"], "usage-error", "arguments: {arguments:?}");
    }

    // The flag only counts for the commands that define it.
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["check", "--json"])
        .current_dir(directory.path())
        .output()
        .expect("run evidencectl");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "check has no legacy --json flag");
}
