use std::{fs, path::Path, process::Command};

use serde_json::Value;
use sha2::{Digest as _, Sha256};

fn assert_json_format_refusal(arguments: &[&str], expected_command: &str) {
    let directory = tempfile::tempdir().expect("temporary working directory");
    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(["--format", "json"])
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

#[test]
fn global_json_refuses_every_legacy_human_renderer_before_dispatch() {
    let cases: &[(&[&str], &str)] = &[
        (
            &[
                "client",
                "contracts",
                "fetch",
                "--profile",
                "client.json",
                "--output",
                "contracts.json",
            ],
            "client",
        ),
        (&["access", "policy", "list"], "access"),
        (&["keygen", "secret", "--output", "secret"], "keygen"),
        (&["jwks", "--output", "jwks.json", "public.jwk"], "jwks"),
        (
            &["source", "suggest", "--openapi", "source.openapi.yaml"],
            "source",
        ),
        (&["source", "mock", "check"], "source"),
        (&["source", "detach", "records"], "source"),
        (&["target", "new", "target", "--local"], "target new"),
        (
            &["request", "prepare", "question", "--name", "request"],
            "request",
        ),
        (
            &[
                "verify",
                "response.jwt",
                "--context",
                "verification.json",
                "--output",
                "verified.json",
            ],
            "verify",
        ),
        (&["audit", "show", "--last-operation"], "audit"),
        (&["tooling", "editor"], "tooling"),
        (&["tooling", "language-server"], "tooling"),
        (
            &[
                "__dev-supervisor",
                "--dev-root",
                "dev",
                "--evidence-bin",
                "evidence",
                "--mint-bin",
                "mint",
                "--ready-timeout-seconds",
                "1",
            ],
            "__dev-supervisor",
        ),
    ];

    for (arguments, command) in cases {
        assert_json_format_refusal(arguments, command);
    }
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
