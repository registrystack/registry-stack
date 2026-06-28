// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::Command;

const FORBIDDEN_DOMAINS: &[&str] = &[
    concat!("registry-relay", ".dev"),
    concat!("registry-notary", ".dev"),
    concat!("docs.registry-notary", ".dev"),
    concat!("registry-platform", ".dev"),
    concat!("registry-platform", ".example"),
    concat!("registry-manifest", ".dev"),
    concat!("registry-metadata", ".dev"),
    concat!("schemas.registry-relay", ".org"),
];

const ALLOWED_HISTORICAL_FILES: &[&str] =
    &["docs/site/src/content/docs/decisions/rename-2026-05-23.mdx"];

#[test]
fn registry_owned_identifiers_use_registrystack_domain() {
    let repo = repo_root();
    let output = Command::new("git")
        .arg("ls-files")
        .arg("-z")
        .current_dir(&repo)
        .output()
        .expect("git ls-files runs");
    assert!(
        output.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut findings = Vec::new();
    for raw_path in output.stdout.split(|byte| *byte == 0) {
        if raw_path.is_empty() {
            continue;
        }
        let relative = String::from_utf8(raw_path.to_vec()).expect("tracked path is utf-8");
        if ALLOWED_HISTORICAL_FILES.contains(&relative.as_str()) {
            continue;
        }
        let path = repo.join(&relative);
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        for domain in FORBIDDEN_DOMAINS {
            if contents.contains(domain) {
                findings.push(format!("{relative}: contains {domain}"));
            }
        }
    }

    assert!(
        findings.is_empty(),
        "Registry-owned identifiers must use https://id.registrystack.org/:\n{}",
        findings.join("\n")
    );
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("registryctl lives under crates/")
        .to_path_buf()
}
