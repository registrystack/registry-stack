// SPDX-License-Identifier: Apache-2.0
use std::{fs, path::Path, process::Command};

#[test]
fn production_refuses_hosted_development_start_before_writing() {
    let root = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_registry-render"))
        .args(["rstack-dev", "start"])
        .arg(root.path())
        .env("REGISTRY_STACK_POSTURE", "production")
        .env("RSTACK_DEV_STATE_DIR", root.path().join("state"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("platform.posture.conflict"), "{stderr}");
    assert!(output.stdout.is_empty());
    assert!(root.path().read_dir().unwrap().next().is_none());
}

#[test]
fn serve_defaults_to_production_and_refuses_a_test_issuer() {
    let root = tempfile::tempdir().unwrap();
    let runtime = root.path().join("runtime.yaml");
    let package = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/render/bundles/receipt")
        .canonicalize()
        .unwrap();
    fs::write(
        &runtime,
        format!(
            "apiVersion: id.registrystack.org/formats/render/runtime/v1alpha1
kind: RenderRuntimeConfig
listener:
  bind: 127.0.0.1:8080
package:
  root: {}
secretProviders:
  file:
    root: {}/secrets
authentication:
  oidc:
    issuers:
      main:
        issuer: https://issuer.example.test
        audience: https://render.example.test
        allowedClients: [portal]
        jwksSource:
          type: test-issuer
          documentRef: secret:file/jwks.json
audit:
  path: /var/lib/render/audit/render.jsonl
",
            package.display(),
            root.path().display()
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_registry-render"))
        .args(["serve", "--runtime-config"])
        .arg(runtime)
        .env_remove("REGISTRY_STACK_POSTURE")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("platform.posture.test-issuer"), "{stderr}");
}
