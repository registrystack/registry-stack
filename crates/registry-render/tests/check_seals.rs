// SPDX-License-Identifier: Apache-2.0

//! `registry-render check` resolves a bundle's `seal` members against the
//! runtime file's `signing.seals` when both are given.

use std::path::{Path, PathBuf};
use std::process::Command;

const SEAL: &str = "    ministry:\n      privateKeyRef: secret:file/seal.jwk\n      certificateChainFile: /etc/render/seal/chain.pem\n      timestampAuthority:\n        url: https://tsa.example.test/tsr\n      allowedClients: [records-service]\n";

fn registry_render() -> Command {
    Command::new(env!("CARGO_BIN_EXE_registry-render"))
}

/// A scaffolded bundle whose first document type names the seal `ministry`.
fn sealed_bundle(home: &Path) -> PathBuf {
    let bundle = home.join("bundle");
    let init = registry_render().arg("init").arg(&bundle).output().unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let manifest = bundle.join("manifest.yaml");
    let text = std::fs::read_to_string(&manifest).unwrap();
    assert!(text.contains("    entryFile:"), "{text}");
    std::fs::write(
        &manifest,
        text.replacen("    entryFile:", "    seal: ministry\n    entryFile:", 1),
    )
    .unwrap();
    bundle
}

fn runtime(home: &Path, signing: &str) -> PathBuf {
    let path = home.join("runtime.yaml");
    std::fs::write(
        &path,
        format!(
            "apiVersion: id.registrystack.org/formats/render/runtime/v1alpha1\nkind: RenderRuntimeConfig\nlistener:\n  bind: 127.0.0.1:8080\npackage:\n  root: /srv/render/package\nsecretProviders:\n  file:\n    root: {}\nauth:\n  oidc:\n    issuer: https://issuer.example.test\n    audience: https://render.example.test\n    allowedClients: [portal, records-service]\naudit:\n  path: /var/lib/render/audit/render.jsonl\n{signing}",
            home.join("secrets").display()
        ),
    )
    .unwrap();
    path
}

fn check(bundle: &Path, runtime: &Path) -> (Option<i32>, serde_json::Value) {
    let output = registry_render()
        .args(["check", "--bundle"])
        .arg(bundle)
        .arg("--runtime-config")
        .arg(runtime)
        .args(["--format", "json"])
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code(), report)
}

fn codes(report: &serde_json::Value) -> Vec<(String, String)> {
    report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["severity"].as_str().unwrap().to_owned(),
                d["code"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn check_resolves_bundle_seals_against_the_runtime_bindings() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().canonicalize().unwrap();
    let bundle = sealed_bundle(&home);

    // A bound seal passes, and the report names the seal each document uses.
    let bound = runtime(&home, &format!("signing:\n  seals:\n{SEAL}"));
    let (exit, report) = check(&bundle, &bound);
    assert_eq!(exit, Some(0), "{report}");
    assert!(codes(&report).is_empty(), "{report}");
    assert_eq!(report["bundle"]["documents"][0]["seal"], "ministry");

    // A seal the runtime does not bind is refused at the runtime file, and
    // the seal the bundle never names is only a warning.
    let other = runtime(
        &home,
        &format!(
            "signing:\n  seals:\n{}",
            SEAL.replace("ministry", "regional")
        ),
    );
    let (exit, report) = check(&bundle, &other);
    assert_eq!(exit, Some(1), "{report}");
    assert_eq!(
        codes(&report),
        [
            (
                "error".to_owned(),
                "render.runtime.seal-not-bound".to_owned()
            ),
            (
                "warning".to_owned(),
                "render.runtime.seal-unused".to_owned()
            ),
        ]
    );
    assert_eq!(report["errors"], 1);
    assert_eq!(report["warnings"], 1);
    let file = other.display().to_string();
    assert_eq!(report["diagnostics"][0]["source"]["file"], file);

    // Without a signing block sealing is off and the package still checks.
    let off = runtime(&home, "");
    let (exit, report) = check(&bundle, &off);
    assert_eq!(exit, Some(0), "{report}");
    assert!(codes(&report).is_empty(), "{report}");
}
