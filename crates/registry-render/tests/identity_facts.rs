// SPDX-License-Identifier: Apache-2.0

//! `registry-render generate identity-facts` writes the facts a deployment
//! states about its issuer from its runtime file and package.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SEAL: &str = "    ministry:\n      signer:\n        type: local-jwk\n        privateKeyRef: secret:file/seal.jwk\n      certificateChainFile: /etc/render/seal/chain.pem\n      timestampAuthority:\n        url: https://tsa.example.test/tsr\n      allowedClients: [records-service]\n";

fn registry_render() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-render"));
    command.env_remove("REGISTRY_STACK_POSTURE");
    command
}

/// A scaffolded package source whose first document type names the seal
/// `ministry` when `sealed`.
fn bundle(home: &Path, sealed: bool) -> PathBuf {
    let bundle = home.join("bundle");
    let init = registry_render().arg("init").arg(&bundle).output().unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    if sealed {
        let manifest = bundle.join("manifest.yaml");
        let text = std::fs::read_to_string(&manifest).unwrap();
        std::fs::write(
            &manifest,
            text.replacen("    entryFile:", "    seal: ministry\n    entryFile:", 1),
        )
        .unwrap();
    }
    bundle
}

/// A runtime file whose `oidc` block is `issuers`, with `siblings` beside it.
fn runtime(home: &Path, issuers: &str, siblings: &str, sealed: bool) -> PathBuf {
    let signing = if sealed {
        format!("assuranceProfile: local\nsigning:\n  seals:\n{SEAL}")
    } else {
        String::new()
    };
    let path = home.join("runtime.yaml");
    std::fs::write(
        &path,
        format!(
            "apiVersion: id.registrystack.org/formats/render/runtime/v1alpha1\nkind: RenderRuntimeConfig\nlistener:\n  bind: 127.0.0.1:8080\npackage:\n  root: /srv/render/package\nsecretProviders:\n  file:\n    root: {}\nauthentication:\n  oidc:\n{siblings}    issuers:\n{issuers}audit:\n  path: /var/lib/render/audit/render.jsonl\n{signing}",
            home.join("secrets").display()
        ),
    )
    .unwrap();
    path
}

const STAFF: &str = "      staff:\n        issuer: https://id.example.test/realms/staff\n        audience: https://render.example.test\n        allowedClients: [portal, records-service]\n";
const PARTNERS: &str = "      partners:\n        issuer: https://login.partner.example/v2.0\n        audience: https://render.example.test\n        allowedClients: [batch]\n";

fn generate(bundle: &Path, runtime: &Path, output: &Path, extra: &[&str]) -> Output {
    registry_render()
        .args(["generate", "identity-facts"])
        .arg(bundle)
        .arg("--runtime-config")
        .arg(runtime)
        .arg("--output")
        .arg(output)
        .args(["--posture", "development"])
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn the_facts_state_the_issuer_the_clients_and_each_routes_scope() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().canonicalize().unwrap();
    let package = bundle(&home, true);
    let runtime = runtime(&home, STAFF, "", true);
    let output = home.join("facts.yaml");
    let result = generate(&package, &runtime, &output, &[]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&output).unwrap(),
        "apiVersion: id.registrystack.org/formats/platform/identity-facts/v1\nkind: PlatformIdentityFacts\nproduct: render\nissuer: https://id.example.test/realms/staff\naudience: https://render.example.test\nallowedClients:\n- portal\n- records-service\naccessProfiles:\n- id: render\n  scopes:\n  - render:render\n- id: seal\n  scopes:\n  - render:seal\n  requesterClients:\n  - records-service\n"
    );
}

#[test]
fn configured_scope_names_reach_the_facts_and_a_package_without_seals_has_no_seal_profile() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().canonicalize().unwrap();
    let package = bundle(&home, false);
    let runtime = runtime(
        &home,
        STAFF,
        "    renderScope: documents:render\n    sealScope: documents:seal\n",
        false,
    );
    let output = home.join("facts.yaml");
    let result = generate(&package, &runtime, &output, &[]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let facts = std::fs::read_to_string(&output).unwrap();
    assert!(facts.contains("- documents:render"), "{facts}");
    assert!(!facts.contains("documents:seal"), "{facts}");
    assert!(!facts.contains("id: seal"), "{facts}");
}

#[test]
fn two_issuers_need_the_issuer_named_and_an_unknown_one_is_refused() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().canonicalize().unwrap();
    let package = bundle(&home, false);
    let runtime = runtime(&home, &format!("{STAFF}{PARTNERS}"), "", false);
    let output = home.join("facts.yaml");

    let missing = generate(&package, &runtime, &output, &[]);
    assert!(!missing.status.success());
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(
        stderr.contains("identity.facts.issuer-required"),
        "{stderr}"
    );
    assert!(!output.exists(), "a refusal writes nothing");

    let unknown = generate(&package, &runtime, &output, &["--issuer", "elsewhere"]);
    assert!(!unknown.status.success());
    let stderr = String::from_utf8_lossy(&unknown.stderr);
    assert!(stderr.contains("identity.facts.unknown-issuer"), "{stderr}");

    let named = generate(&package, &runtime, &output, &["--issuer", "partners"]);
    assert!(
        named.status.success(),
        "{}",
        String::from_utf8_lossy(&named.stderr)
    );
    let facts = std::fs::read_to_string(&output).unwrap();
    assert!(facts.contains("login.partner.example"), "{facts}");
    assert!(!facts.contains("id.example.test"), "{facts}");
}

#[test]
fn an_existing_output_file_is_never_replaced() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().canonicalize().unwrap();
    let package = bundle(&home, false);
    let runtime = runtime(&home, STAFF, "", false);
    let output = home.join("facts.yaml");
    std::fs::write(&output, "keep").unwrap();
    let result = generate(&package, &runtime, &output, &[]);
    assert!(!result.status.success());
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "keep");
}

#[test]
fn an_issuer_that_carries_no_seal_client_states_only_the_render_profile() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().canonicalize().unwrap();
    let package = bundle(&home, true);
    let runtime = runtime(&home, &format!("{STAFF}{PARTNERS}"), "", true);

    let partners = home.join("partners.yaml");
    let result = generate(&package, &runtime, &partners, &["--issuer", "partners"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let facts = std::fs::read_to_string(&partners).unwrap();
    assert!(facts.contains("id: render"), "{facts}");
    assert!(!facts.contains("id: seal"), "{facts}");

    let staff = home.join("staff.yaml");
    let result = generate(&package, &runtime, &staff, &["--issuer", "staff"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let facts = std::fs::read_to_string(&staff).unwrap();
    assert!(facts.contains("id: seal"), "{facts}");
    assert!(facts.contains("- records-service"), "{facts}");
}
