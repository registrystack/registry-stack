use std::fs;
use std::process::Command;

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rstack"))
        .args(arguments)
        .output()
        .expect("run rstack")
}

fn write_connection(directory: &std::path::Path, scope: &str) -> std::path::PathBuf {
    let path = directory.join("connection.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "apiVersion": "id.registrystack.org/formats/platform/python-connection/v1alpha1",
            "kind": "PlatformPythonConnection",
            "service": "licensing-portal",
            "audience": "holder",
            "secretProviders": {"environment": {}},
            "bindings": [{
                "name": "licensing-registry",
                "product": "breg",
                "url": "https://registry.example.invalid/secret-looking-path",
                "default": true,
                "credential": {
                    "type": "private-key-jwt",
                    "tokenEndpoint": "https://identity.example.invalid/oauth/token",
                    "clientId": "licensing-portal",
                    "clientKeyRef": "secret:env/GRANTS_REPORT_CANARY",
                    "resource": "urn:example:licensing",
                    "scopes": [scope]
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    path
}

fn write_facts(directory: &std::path::Path) -> std::path::PathBuf {
    let path = directory.join("breg-facts.yaml");
    fs::write(
        &path,
        r#"apiVersion: id.registrystack.org/formats/platform/identity-facts/v1
kind: PlatformIdentityFacts
product: breg
issuer: https://identity.example.invalid
audience: urn:example:licensing
allowedClients: [licensing-portal]
claims:
  registry_principal: string
accessProfiles:
  - id: holder-read
    scopes: [licensing:read]
    requiredClaims: [registry_principal]
"#,
    )
    .unwrap();
    path
}

#[test]
fn json_report_names_known_binding_profile_provenance_and_limits() {
    let scratch = tempfile::tempdir().unwrap();
    let connection = write_connection(scratch.path(), "licensing:read");
    let facts = write_facts(scratch.path());

    let output = run(&[
        "grants",
        connection.to_str().unwrap(),
        "--facts",
        facts.to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], "registry.rstack.grants.v1");
    assert_eq!(report["status"], "advisory");
    assert_eq!(report["connection"]["source"], connection.to_str().unwrap());
    assert_eq!(report["bindings"][0]["name"], "licensing-registry");
    assert_eq!(report["bindings"][0]["product"], "breg");
    assert_eq!(
        report["bindings"][0]["source"],
        connection.to_str().unwrap()
    );
    assert_eq!(report["bindings"][0]["path"], "/bindings/0");
    assert_eq!(report["bindings"][0]["resource"], "urn:example:licensing");
    assert_eq!(
        report["bindings"][0]["configuredScopes"],
        serde_json::json!(["licensing:read"])
    );
    assert_eq!(
        report["bindings"][0]["knownProfiles"][0]["id"],
        "holder-read"
    );
    assert_eq!(
        report["bindings"][0]["knownProfiles"][0]["source"],
        facts.to_str().unwrap()
    );
    assert_eq!(
        report["bindings"][0]["knownProfiles"][0]["matchBasis"],
        "scope-subset"
    );
    assert!(report["bindings"][0]["omissions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["code"] == "binding-profile-derived-from-scopes"));
    assert_eq!(report["facts"][0]["product"], "breg");
    assert_eq!(report["facts"][0]["resource"], "urn:example:licensing");
    assert_eq!(report["facts"][0]["source"], facts.to_str().unwrap());
    assert_eq!(
        report["facts"][0]["profiles"][0]["path"],
        "/accessProfiles/0"
    );
    assert!(report["omissions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["code"] == "live-grants-not-inspected"));
    assert!(report["omissions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["code"] == "record-sensitivity-not-classified"));

    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("GRANTS_REPORT_CANARY"), "{text}");
    assert!(!text.contains("secret-looking-path"), "{text}");
    assert!(!text.contains("oauth/token"), "{text}");
}

#[test]
fn unknown_external_grant_is_reported_without_refusal_or_false_certificate() {
    let scratch = tempfile::tempdir().unwrap();
    let connection = write_connection(scratch.path(), "external:unknown");
    let facts = write_facts(scratch.path());

    let output = run(&[
        "--format=json",
        "grants",
        connection.to_str().unwrap(),
        "--facts",
        facts.to_str().unwrap(),
    ]);

    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "advisory");
    assert_eq!(
        report["bindings"][0]["knownProfiles"],
        serde_json::json!([])
    );
    assert_eq!(report["bindings"][0]["profileKnowledge"], "unknown");
    assert!(report["bindings"][0]["omissions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["code"] == "binding-profile-not-confirmed"));
}

#[test]
fn human_report_keeps_provenance_and_limits_next_to_the_result() {
    let scratch = tempfile::tempdir().unwrap();
    let connection = write_connection(scratch.path(), "licensing:read");
    let facts = write_facts(scratch.path());

    let output = run(&[
        "grants",
        connection.to_str().unwrap(),
        "--facts",
        facts.to_str().unwrap(),
    ]);

    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Advisory grants report"), "{text}");
    assert!(
        text.contains("holder-read (scope-subset, source:"),
        "{text}"
    );
    assert!(text.contains("live-grants-not-inspected"), "{text}");
    assert!(
        text.contains("binding-profile-derived-from-scopes"),
        "{text}"
    );
    assert!(!text.contains("GRANTS_REPORT_CANARY"), "{text}");
}

#[test]
fn refused_input_does_not_repeat_values_from_the_connection() {
    let scratch = tempfile::tempdir().unwrap();
    let connection = scratch.path().join("connection.json");
    fs::write(
        &connection,
        r#"{"service":"DO-NOT-REPEAT-THIS","bindings":"DO-NOT-REPEAT-EITHER"}"#,
    )
    .unwrap();

    let output = run(&["grants", connection.to_str().unwrap(), "--format", "json"]);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("DO-NOT-REPEAT"), "{text}");
    let report: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["error"]["class"], "domain");
}
