// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::{Command, Output};

fn fixture(directory: &Path, second: bool) {
    let project = concat!(
        include_str!("fixtures/minimal/project.yaml"),
        "  - id: records-reader\n    scopes: [records:read]\n    operations: [cases-get]\n    recordTypes: [case]\n"
    );
    std::fs::write(directory.join("project.yaml"), project).unwrap();
    let entries = if second {
        "    partner: {issuer: 'https://partner.example.test', audience: urn:registry:adapter-api, allowedClients: [partner-client]}\n"
    } else {
        ""
    };
    std::fs::write(
        directory.join("runtime.yaml"),
        format!(
            "apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1\nkind: AdapterRuntimeConfig\nid: facts-test\nendpoints: []\nlistener: {{bind: '127.0.0.1:8080'}}\ndatabase: {{runtimeUrlRef: 'secret:env/DB', migrationUrlRef: 'secret:env/DB'}}\nallowedPrivateCidrs: ['10.0.0.0/8']\naudit: {{retentionDays: 90}}\noidc:\n  issuers:\n    primary: {{issuer: 'https://primary.example.test', audience: urn:registry:adapter-api, allowedClients: [coordinator-payments], scopeClaim: adapter_scopes}}\n{entries}"
        ),
    )
    .unwrap();
    std::fs::write(
        directory.join("payments.yaml"),
        include_str!(
            "../../../products/adapter/examples/payment-collections/payments.mifos.example.yaml"
        ),
    )
    .unwrap();
}

fn generate(directory: &Path, flags: &[&str]) -> Output {
    generate_to(directory, &directory.join("facts.yaml"), flags)
}

fn generate_to(directory: &Path, output: &Path, flags: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_adapterctl"))
        .args(["--format", "json", "generate", "identity-facts"])
        .arg(directory.join("project.yaml"))
        .arg("--runtime-config")
        .arg(directory.join("runtime.yaml"))
        .arg("--output")
        .arg(output)
        .env("REGISTRY_STACK_POSTURE", "development")
        .args(flags)
        .output()
        .unwrap()
}

#[test]
fn facts_describe_the_selected_issuer_and_its_payment_connections() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), true);
    let payments = root.path().join("payments.yaml");
    let result = generate(
        root.path(),
        &[
            "--issuer",
            "primary",
            "--payments-config",
            payments.to_str().unwrap(),
        ],
    );
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        std::fs::read_to_string(root.path().join("facts.yaml")).unwrap(),
        include_str!("fixtures/identity-facts.yaml")
    );
}

#[test]
fn an_issuer_is_required_for_more_than_one_entry() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), true);
    let result = generate(root.path(), &[]);
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("identity.facts.issuer-required"),
        "{result:?}"
    );
    assert!(!root.path().join("facts.yaml").exists());
}

#[test]
fn an_unknown_issuer_is_refused() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), false);
    let result = generate(root.path(), &["--issuer", "unknown"]);
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("identity.facts.unknown-issuer"),
        "{result:?}"
    );
}

#[test]
fn the_only_issuer_is_selected_without_a_flag() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), false);
    let result = generate(root.path(), &[]);
    assert!(result.status.success(), "{result:?}");
    let facts = std::fs::read_to_string(root.path().join("facts.yaml")).unwrap();
    assert!(
        facts.contains("issuer: https://primary.example.test"),
        "{facts}"
    );
}

#[test]
fn an_existing_output_is_left_untouched() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), false);
    let output = root.path().join("facts.yaml");
    std::fs::write(&output, "existing content").unwrap();
    let result = generate(root.path(), &[]);
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("output.exists"),
        "{result:?}"
    );
    assert_eq!(std::fs::read_to_string(output).unwrap(), "existing content");
}

#[test]
fn a_missing_runtime_names_the_file_and_fails_operationally() {
    assert_missing_input("runtime.yaml");
}

#[test]
fn missing_payments_names_the_file_and_fails_operationally() {
    assert_missing_input("payments.yaml");
}

fn assert_missing_input(file: &str) {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), false);
    let missing = root.path().join(file);
    std::fs::remove_file(&missing).unwrap();
    let payments = root.path().join("payments.yaml");
    let result = generate(
        root.path(),
        &["--payments-config", payments.to_str().unwrap()],
    );
    let report = String::from_utf8(result.stdout).unwrap();
    assert_eq!(result.status.code(), Some(3), "{report}");
    assert!(report.contains(missing.to_str().unwrap()), "{report}");
    assert!(!root.path().join("facts.yaml").exists());
}

#[test]
fn a_reader_refusal_names_the_source_profile_and_rule() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), false);
    let project = root.path().join("project.yaml");
    let text = std::fs::read_to_string(&project).unwrap();
    let scopes = (0..33)
        .map(|i| format!("records:{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        project,
        text.replace("records:read]", &format!("{scopes}]")),
    )
    .unwrap();
    let result = generate(root.path(), &[]);
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let finding = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["code"] == "identity.facts.invalid-scopes")
        .unwrap();
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains("records-reader"),
        "{finding}"
    );
    assert!(
        finding["suggestedAction"]
            .as_str()
            .is_some_and(|action| !action.is_empty()),
        "{finding}"
    );
}

#[test]
fn a_facade_and_payment_profile_collision_names_both_sources() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), false);
    let payments = root.path().join("payments.yaml");
    let fixture = std::fs::read_to_string(&payments).unwrap();
    let connection_id = fixture
        .lines()
        .find_map(|line| line.strip_prefix("  - id: "))
        .unwrap();
    let project = root.path().join("project.yaml");
    let text = std::fs::read_to_string(&project).unwrap();
    std::fs::write(project, text.replace("records-reader", connection_id)).unwrap();
    let result = generate(
        root.path(),
        &["--payments-config", payments.to_str().unwrap()],
    );
    let report = String::from_utf8(result.stdout).unwrap();
    assert_eq!(result.status.code(), Some(1), "{report}");
    assert!(report.contains("identity.facts.unstatable"), "{report}");
    assert!(report.contains("/accessProfiles/1/id"), "{report}");
    assert!(report.contains("/connections/0/id"), "{report}");
}

#[test]
fn invalid_payment_connections_keep_the_validation_code() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), false);
    let payments = root.path().join("payments.yaml");
    let example = std::fs::read_to_string(&payments).unwrap();
    let header = example.split_once("connections:").unwrap().0;
    std::fs::write(&payments, format!("{header}connections: []\n")).unwrap();
    let result = generate(
        root.path(),
        &["--payments-config", payments.to_str().unwrap()],
    );
    let report = String::from_utf8(result.stdout).unwrap();
    assert_eq!(result.status.code(), Some(1), "{report}");
    assert!(report.contains("adapter.payment.configuration"), "{report}");
    assert!(report.contains(payments.to_str().unwrap()), "{report}");
}

#[test]
fn a_failed_write_names_the_output_file_and_the_io_cause() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), false);
    let output = root.path().join("absent/facts.yaml");
    let result = generate_to(root.path(), &output, &[]);
    let report = String::from_utf8(result.stdout).unwrap();
    assert_eq!(result.status.code(), Some(3), "{report}");
    assert!(report.contains("output.failed"), "{report}");
    assert!(report.contains(output.to_str().unwrap()), "{report}");
    let cause = std::fs::File::open(&output).unwrap_err().to_string();
    assert!(report.contains(&cause), "{report}");
}

#[test]
fn a_payment_profile_refusal_locates_the_connection_without_echoing_substitution() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path(), false);
    let payments = root.path().join("payments.yaml");
    let text = std::fs::read_to_string(&payments)
        .unwrap()
        .replacen(
            "id: licence-fees",
            "id: '${ADAPTER_TEST_CONNECTION_ID:-private-payment-id}'",
            1,
        )
        .replacen(
            "requiredScope: payments:collect",
            "requiredScope: 'payments:*'",
            1,
        );
    std::fs::write(&payments, text).unwrap();
    let result = generate(
        root.path(),
        &["--payments-config", payments.to_str().unwrap()],
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let finding = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["code"] == "identity.facts.invalid-scopes")
        .unwrap();
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains("/connections/0"),
        "{finding}"
    );
    assert!(
        !report.to_string().contains("private-payment-id"),
        "{report}"
    );
    assert!(
        finding["suggestedAction"]
            .as_str()
            .is_some_and(|action| !action.is_empty()),
        "{finding}"
    );
}
