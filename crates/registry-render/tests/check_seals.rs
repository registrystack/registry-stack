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

/// A seal certificate with an extension of `bytes` octets, to make a chain
/// too large for the signature space a seal may reserve.
fn oversized(params: &mut rcgen::CertificateParams, bytes: usize) {
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 55555, 1],
            vec![0x5a; bytes],
        ));
}

/// `check --environment` on a runtime whose one seal reads the chain at
/// `chain`.
fn check_chain(home: &Path, bundle: &Path, chain: &Path) -> (Option<i32>, serde_json::Value) {
    let seal = SEAL.replace("/etc/render/seal/chain.pem", &chain.display().to_string());
    let runtime = runtime(home, &format!("signing:\n  seals:\n{seal}"));
    let output = registry_render()
        .args(["check", "--bundle"])
        .arg(bundle)
        .arg("--runtime-config")
        .arg(&runtime)
        .args(["--environment", "--format", "json"])
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

#[test]
fn check_with_the_environment_reads_each_seal_certificate_chain() {
    use registry_platform_crypto::document_signature::test_support::TestPki;
    use registry_platform_crypto::SigningAlgorithm;

    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().canonicalize().unwrap();
    let bundle = sealed_bundle(&home);
    let chain = home.join("chain.pem");
    let pki = TestPki::generate().unwrap();
    let now = time::OffsetDateTime::now_utc();
    let pointer = "/signing/seals/ministry/certificateChainFile";
    let issue = |customise: &dyn Fn(&mut rcgen::CertificateParams)| {
        let seal = pki
            .issue_seal_with(SigningAlgorithm::Es256, |params| customise(params))
            .unwrap();
        std::fs::write(&chain, seal.chain_pem()).unwrap();
    };

    // A usable chain passes. The seal's private key is never read: the
    // secret provider root does not even exist.
    issue(&|_| {});
    let (exit, report) = check_chain(&home, &bundle, &chain);
    assert_eq!(exit, Some(0), "{report}");
    assert!(codes(&report).is_empty(), "{report}");

    let cases: [(
        &dyn Fn(&mut rcgen::CertificateParams),
        Option<i32>,
        &str,
        &str,
    ); 5] = [
        (
            &|params| params.not_after = now + time::Duration::days(10),
            Some(0),
            "warning",
            "render.runtime.seal-certificate-expiring",
        ),
        (
            &|params| {
                params.not_before = now - time::Duration::days(30);
                params.not_after = now - time::Duration::days(1);
            },
            Some(0),
            "warning",
            "render.runtime.seal-certificate-expired",
        ),
        (
            &|params| params.not_before = now + time::Duration::days(1),
            Some(0),
            "warning",
            "render.runtime.seal-certificate-not-yet-valid",
        ),
        (
            &|params| params.key_usages = vec![rcgen::KeyUsagePurpose::KeyEncipherment],
            Some(1),
            "error",
            "render.runtime.seal-certificate-usage",
        ),
        (
            &|params| oversized(params, 90 * 1024),
            Some(1),
            "error",
            "render.runtime.seal-chain-too-large",
        ),
    ];
    for (customise, expected_exit, severity, code) in cases {
        issue(customise);
        let (exit, report) = check_chain(&home, &bundle, &chain);
        assert_eq!(exit, expected_exit, "{code}: {report}");
        assert_eq!(
            codes(&report),
            [(severity.to_owned(), code.to_owned())],
            "{report}"
        );
        assert_eq!(report["diagnostics"][0]["path"], pointer, "{report}");
        let message = report["diagnostics"][0]["message"].as_str().unwrap();
        for value in ["Registry Stack Test", &home.display().to_string()] {
            assert!(!message.contains(value), "value-free: {message}");
        }
    }

    std::fs::write(&chain, "not a certificate\n").unwrap();
    let (exit, report) = check_chain(&home, &bundle, &chain);
    assert_eq!(exit, Some(1), "{report}");
    assert_eq!(
        codes(&report),
        [(
            "error".to_owned(),
            "render.runtime.seal-chain-invalid".to_owned()
        )]
    );

    let (exit, report) = check_chain(&home, &bundle, &home.join("absent.pem"));
    assert_eq!(exit, Some(1), "{report}");
    assert_eq!(
        codes(&report),
        [(
            "error".to_owned(),
            "render.runtime.seal-chain-unreadable".to_owned()
        )]
    );
}
