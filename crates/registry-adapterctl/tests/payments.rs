// SPDX-License-Identifier: Apache-2.0
use std::{path::PathBuf, process::ExitCode};

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
