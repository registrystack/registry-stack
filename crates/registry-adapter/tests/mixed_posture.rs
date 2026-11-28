// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::Command;

#[test]
fn mixed_serve_lists_development_settings_from_both_files() {
    let root = tempfile::tempdir().unwrap();
    let runtime = root.path().join("runtime.yaml");
    std::fs::write(
        &runtime,
        r#"apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: mixed-posture-test
endpoints: []
listener:
  bind: 127.0.0.1:0
database:
  runtimeUrlRef: secret:env/MIXED_TEST_DB
  migrationUrlRef: secret:env/MIXED_TEST_DB
oidc:
  issuers:
    primary:
      issuer: http://127.0.0.1:9
      audience: test
      allowInsecureHttp: true
      allowedClients: [test]
allowedPrivateCidrs: [192.168.0.0/16]
audit:
  retentionDays: 90
"#,
    )
    .unwrap();
    let adapter = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter");
    let payments = adapter.join("examples/payment-collections/payments.example.yaml");
    let project =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../registry-adapterctl/tests/fixtures/minimal");
    for flags in [&[][..], &["--posture", "development"][..]] {
        let output = Command::new(env!("CARGO_BIN_EXE_adapter"))
            .args(["serve", "--runtime-config"])
            .arg(&runtime)
            .arg("--project")
            .arg(&project)
            .arg("--payments-config")
            .arg(&payments)
            .env_remove("REGISTRY_STACK_POSTURE")
            .env_remove("MIXED_TEST_DB")
            .args(flags)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let logs = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for (code, pointer, file) in [
            (
                "platform.posture.insecure-issuer-http",
                "/oidc/issuers/primary/allowInsecureHttp",
                "runtime.yaml",
            ),
            (
                "adapter.posture.payment-simulator",
                "/connections/0/binding/provider",
                "payments.example.yaml",
            ),
        ] {
            assert!(
                logs.lines().any(|line| {
                    line.contains(code) && line.contains(pointer) && line.contains(file)
                }),
                "missing located {code}: {logs}"
            );
        }
        if flags.is_empty() {
            assert!(logs.contains("the configuration was refused"), "{logs}");
            assert!(
                logs.contains("accepted only when the process declares development"),
                "{logs}"
            );
        } else {
            let declared = logs
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .find(|line| line["fields"]["message"] == "posture declared")
                .unwrap_or_else(|| panic!("{logs}"));
            assert_eq!(declared["fields"]["development_settings"], 2, "{declared}");
            assert!(
                !logs.contains("accepted only when the process declares development"),
                "{logs}"
            );
        }
    }
}
