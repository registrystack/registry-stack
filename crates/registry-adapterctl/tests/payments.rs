// SPDX-License-Identifier: Apache-2.0
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

const MAPPED_PROVIDER_SCRIPT: &str = r#"
fn submit_request(intent, settings, acceptance) {
    if settings == () || acceptance != () { throw "invalid submit context"; }
    #{pathParameters: #{}, query: #{}, headers: #{}, body: #{correlation: intent.correlationId}}
}
fn submit_response(intent, settings, acceptance, response) {
    if settings == () || acceptance != () || response == () { throw "invalid submit context"; }
    #{correlationId: intent.correlationId, references: #{transaction: "accepted"}}
}
fn status_request(intent, settings, acceptance) {
    if intent == () || settings == () || acceptance == () { throw "status needs context"; }
    #{pathParameters: #{}, query: #{}, headers: #{}, body: ()}
}
fn status_response(intent, settings, acceptance, response) {
    if settings == () || acceptance == () || response == () { throw "status needs context"; }
    #{
        correlationId: intent.correlationId,
        providerReference: "accepted",
        state: "pending",
        money: intent.money,
        parties: [#{role: "payer", key: intent.source.scheme, value: intent.source.value}]
    }
}
"#;

fn mapped_provider_pack(id: &str) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/payment-provider-pack/v1alpha1
kind: AdapterPaymentProviderPack
id: {id}
version: '1'
connector: adapter-payment-http/v1
capabilities: [collection]
mapping:
  collection:
    auth: bearer
    submit:
      path: /collections
      request: {{file: mapping.rhai, entrypoint: submit_request}}
      response: {{file: mapping.rhai, entrypoint: submit_response}}
    status:
      path: /collections/status
      request: {{file: mapping.rhai, entrypoint: status_request}}
      response: {{file: mapping.rhai, entrypoint: status_response}}
  scripts:
    - path: mapping.rhai
      digest: {}
"#,
        registry_platform_config::sha256_uri(MAPPED_PROVIDER_SCRIPT.as_bytes())
    )
}

fn write_mapped_provider_pack(directory: &Path, id: &str) -> (PathBuf, String) {
    std::fs::write(directory.join("mapping.rhai"), MAPPED_PROVIDER_SCRIPT).unwrap();
    let bytes = mapped_provider_pack(id);
    let path = directory.join(format!("{id}.yaml"));
    std::fs::write(&path, &bytes).unwrap();
    let digest = registry_platform_config::sha256_uri(bytes.as_bytes());
    (path, digest)
}

fn registry_binding() -> Value {
    json!({
        "baseUrl": "http://127.0.0.1:8080/",
        "recordType": "service-fee-bill",
        "recordRoute": "service-fee-bills",
        "readProfile": "payment-adapter-reporter",
        "bindProfile": "payment-adapter-binder",
        "receiptProfile": "payment-adapter-reporter",
        "bindAction": "bind-payment-attempt",
        "receiptAction": "record-payment-receipt",
        "credentialRef": "secret:env/PAYMENT_REPORTER_TOKEN",
        "credentialIdentity": "payment-adapter"
    })
}

fn mapped_collection(id: &str, pack_id: &str, digest: &str) -> Value {
    json!({
        "id": id,
        "institutionId": "ministry",
        "serviceId": id,
        "allowedClients": ["payment-coordinator"],
        "requiredScope": "payments:collections",
        "binding": {
            "providerPack": {"id": pack_id, "version": "1", "digest": digest},
            "simulation": false,
            "currency": "USD",
            "currencyScale": 2,
            "providerCredentialRef": "secret:env/PROVIDER_TOKEN",
            "providerCredentialIdentity": "provider-client",
            "replayWindowSeconds": 3600,
            "provider": {
                "type": "http",
                "submitBaseUrl": "https://submit.example.test/",
                "statusBaseUrl": "https://status.example.test/",
                "settings": {"tenant": "pilot"}
            },
            "registry": registry_binding()
        }
    })
}

fn write_payments(directory: &Path, connections: Vec<Value>) -> PathBuf {
    let path = directory.join("payments.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&json!({
            "apiVersion": "id.registrystack.org/formats/adapter/payments/v1alpha1",
            "kind": "AdapterPayments",
            "connections": connections
        }))
        .unwrap(),
    )
    .unwrap();
    path
}

fn run_json(args: Vec<String>) -> (ExitCode, Value) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = registry_adapterctl::main_entry_from(args, &mut stdout, &mut stderr);
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    (code, serde_json::from_slice(&stdout).unwrap())
}

#[test]
fn payment_connections_can_be_checked_without_secrets_a_registry_project_or_network() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/adapter/examples/payment-collections/payments.example.yaml");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = registry_adapterctl::main_entry_from(
        [
            "adapterctl",
            "--format",
            "json",
            "payments",
            "check",
            path.to_str().unwrap(),
        ],
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(
        code,
        ExitCode::SUCCESS,
        "{}",
        String::from_utf8_lossy(&stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["connectionCount"], 1);
    assert_eq!(report["diagnostics"], serde_json::json!([]));
    assert!(stderr.is_empty());
    assert!(!String::from_utf8(stdout)
        .unwrap()
        .contains("PAYMENT_SIMULATOR_TOKEN"));
}

#[test]
fn payment_check_keeps_the_shared_reader_diagnostic_and_position() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("payments.yaml");
    std::fs::write(&file, "apiVersion: [\n").unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = registry_adapterctl::main_entry_from(
        [
            "adapterctl",
            "--format",
            "json",
            "payments",
            "check",
            file.to_str().unwrap(),
        ],
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(code, ExitCode::from(1));
    let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert!(report["diagnostics"][0]["code"]
        .as_str()
        .unwrap()
        .starts_with("yaml."));
    assert!(report["diagnostics"][0]["source"]["line"].is_number());
    assert!(stderr.is_empty());
}

#[test]
fn payment_provider_variants_keep_nested_source_positions() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("payments.yaml");
    let example = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/examples/payment-collections/payments.example.yaml"),
    )
    .unwrap();
    let marker = "          tenant: pilot\n";
    let marker_end = example.find(marker).unwrap() + marker.len();
    let line = example[..marker_end].lines().count() as u64 + 1;
    std::fs::write(
        &file,
        example.replacen(
            marker,
            &format!("{marker}          conformanceUnknown: true\n"),
            1,
        ),
    )
    .unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = registry_adapterctl::main_entry_from(
        [
            "adapterctl",
            "--format",
            "json",
            "payments",
            "check",
            file.to_str().unwrap(),
        ],
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(code, ExitCode::from(1));
    let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(report["diagnostics"][0]["code"], "config.unknown-key");
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/connections/0/binding/provider/connection/conformanceUnknown"
    );
    assert_eq!(report["diagnostics"][0]["source"]["line"], line);
    assert!(report["diagnostics"][0]["source"]["column"].is_number());
    assert!(stderr.is_empty());
}

#[test]
fn payment_check_consumes_the_exact_pinned_provider_pack() {
    let directory = tempfile::tempdir().unwrap();
    let pack_file = directory.path().join("pack.yaml");
    let pack = "apiVersion: id.registrystack.org/formats/adapter/payment-provider-pack/v1alpha1\nkind: AdapterPaymentProviderPack\nid: simulator\nversion: '1'\nconnector: simulator-p2g/v1\ncapabilities: [collection]\n";
    std::fs::write(&pack_file, pack).unwrap();
    let example = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/examples/payment-collections/payments.example.yaml"),
    )
    .unwrap();
    let pin = format!(
        "    binding:\n      providerPack: {{id: simulator, version: '1', digest: {}}}\n",
        registry_platform_config::sha256_uri(pack.as_bytes())
    );
    let file = directory.path().join("payments.yaml");
    std::fs::write(&file, example.replacen("    binding:\n", &pin, 1)).unwrap();

    let check = |pack: &std::path::Path| {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = registry_adapterctl::main_entry_from(
            [
                "adapterctl",
                "--format",
                "json",
                "payments",
                "check",
                file.to_str().unwrap(),
                "--provider-pack",
                pack.to_str().unwrap(),
            ],
            &mut stdout,
            &mut stderr,
        );
        assert!(stderr.is_empty());
        (
            code,
            serde_json::from_slice::<serde_json::Value>(&stdout).unwrap(),
        )
    };
    let (code, report) = check(&pack_file);
    assert_eq!(code, ExitCode::SUCCESS, "{report}");
    std::fs::write(
        &pack_file,
        pack.replace("simulator-p2g/v1", "mifos-ph-ee-legacy/v1"),
    )
    .unwrap();
    let (code, report) = check(&pack_file);
    assert_eq!(code, ExitCode::from(1));
    assert_eq!(
        report["diagnostics"][0]["code"],
        "adapter.payment.provider-pack-pin"
    );
}

#[test]
fn payment_check_and_contract_accept_distinct_active_provider_pins() {
    let directory = tempfile::tempdir().unwrap();
    let (alpha_path, alpha_digest) = write_mapped_provider_pack(directory.path(), "provider-alpha");
    let (beta_path, beta_digest) = write_mapped_provider_pack(directory.path(), "provider-beta");
    let file = write_payments(
        directory.path(),
        vec![
            mapped_collection("alpha-fees", "provider-alpha", &alpha_digest),
            mapped_collection("beta-fees", "provider-beta", &beta_digest),
        ],
    );

    for command in ["check", "contract"] {
        let (code, report) = run_json(vec![
            "adapterctl".into(),
            "--format".into(),
            "json".into(),
            "payments".into(),
            command.into(),
            file.display().to_string(),
            "--provider-pack".into(),
            alpha_path.display().to_string(),
            "--provider-pack".into(),
            beta_path.display().to_string(),
        ]);
        assert_eq!(code, ExitCode::SUCCESS, "{command}: {report}");
        assert_eq!(report["diagnostics"], json!([]), "{command}: {report}");
        if command == "contract" {
            assert!(report["contract"].is_object(), "{report}");
        }
    }
}

#[test]
fn payment_check_fails_closed_for_a_missing_or_mismatched_active_pack() {
    let directory = tempfile::tempdir().unwrap();
    let (alpha_path, alpha_digest) = write_mapped_provider_pack(directory.path(), "provider-alpha");
    let (beta_path, beta_digest) = write_mapped_provider_pack(directory.path(), "provider-beta");
    let file = write_payments(
        directory.path(),
        vec![
            mapped_collection("alpha-fees", "provider-alpha", &alpha_digest),
            mapped_collection("beta-fees", "provider-beta", &beta_digest),
        ],
    );

    let base = vec![
        "adapterctl".into(),
        "--format".into(),
        "json".into(),
        "payments".into(),
        "check".into(),
        file.display().to_string(),
        "--provider-pack".into(),
        alpha_path.display().to_string(),
    ];
    let (code, report) = run_json(base.clone());
    assert_eq!(code, ExitCode::from(1), "{report}");
    assert!(report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| {
            item["code"] == "adapter.payment.provider-pack-required"
                && item["path"] == "/connections/1/binding/providerPack"
        }));

    std::fs::write(
        &beta_path,
        mapped_provider_pack("provider-beta").replace(
            "capabilities: [collection]",
            "capabilities: [collection]\ntestedVersions: [tampered]",
        ),
    )
    .unwrap();
    let mut mismatched = base;
    mismatched.extend(["--provider-pack".into(), beta_path.display().to_string()]);
    let (code, report) = run_json(mismatched);
    assert_eq!(code, ExitCode::from(1), "{report}");
    assert!(report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| {
            item["code"] == "adapter.payment.provider-pack-pin"
                && item["path"] == "/connections/1/binding/providerPack"
        }));
}

#[test]
fn payment_check_bounds_the_provider_pack_registry() {
    let directory = tempfile::tempdir().unwrap();
    let (pack_path, digest) = write_mapped_provider_pack(directory.path(), "provider-alpha");
    let file = write_payments(
        directory.path(),
        vec![mapped_collection("alpha-fees", "provider-alpha", &digest)],
    );
    let mut args = vec![
        "adapterctl".into(),
        "--format".into(),
        "json".into(),
        "payments".into(),
        "check".into(),
        file.display().to_string(),
    ];
    for _ in 0..33 {
        args.extend(["--provider-pack".into(), pack_path.display().to_string()]);
    }

    let (code, report) = run_json(args);
    assert_eq!(code, ExitCode::from(1), "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "adapter.payment.provider-pack-limit"
    );
}

#[test]
fn payment_check_refuses_ambiguous_multi_pack_fixture_replay() {
    let directory = tempfile::tempdir().unwrap();
    let (alpha_path, alpha_digest) = write_mapped_provider_pack(directory.path(), "provider-alpha");
    let (beta_path, beta_digest) = write_mapped_provider_pack(directory.path(), "provider-beta");
    let file = write_payments(
        directory.path(),
        vec![
            mapped_collection("alpha-fees", "provider-alpha", &alpha_digest),
            mapped_collection("beta-fees", "provider-beta", &beta_digest),
        ],
    );
    let fixture = directory.path().join("fixture.yaml");
    std::fs::write(&fixture, "not inspected when pack selection is ambiguous\n").unwrap();

    let (code, report) = run_json(vec![
        "adapterctl".into(),
        "--format".into(),
        "json".into(),
        "payments".into(),
        "check".into(),
        file.display().to_string(),
        "--provider-pack".into(),
        alpha_path.display().to_string(),
        "--provider-pack".into(),
        beta_path.display().to_string(),
        "--fixtures".into(),
        fixture.display().to_string(),
    ]);
    assert_eq!(code, ExitCode::from(1), "{report}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "adapter.payment.fixture-pack-ambiguous"
    );
}
