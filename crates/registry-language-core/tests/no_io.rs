//! Tripwires for the shared analyzer's pure, bounded snapshot boundary.
//!
//! The package-local clippy configuration is the resolved-symbol guard. These
//! tests cover the two things that guard cannot: source introduced through an
//! unexpected spelling and a newly linked dependency with ambient capability.

#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::{collections::BTreeSet, fs, path::PathBuf};

const PERMITTED_DEPENDENCIES: &[&str] = &[
    "anyhow",
    "getrandom_03",
    "ls-types",
    "registry-evidence-authoring",
    "serde",
    "serde_json",
    "serde_norway",
    "tree-sitter",
    "tree-sitter-yaml",
];

const FORBIDDEN_SOURCE: &[(&str, &str)] = &[
    ("std::fs", "filesystem access"),
    ("std::net", "network access"),
    ("std::process", "process access"),
    ("std::env", "environment access"),
    ("std::time", "clock access"),
    ("std::io", "host stream access"),
    ("getrandom", "ambient randomness"),
    ("rand::", "ambient randomness"),
    ("js_sys", "browser host access"),
    ("web_sys", "browser host access"),
    ("include!", "source outside the guarded source tree"),
    ("include_str!", "compile-time filesystem access"),
    ("include_bytes!", "compile-time filesystem access"),
    ("println!", "host stream output"),
    ("print!", "host stream output"),
    ("eprintln!", "host stream output"),
    ("eprint!", "host stream output"),
    ("dbg!", "host stream output"),
    (".exists()", "filesystem observation"),
    (".try_exists()", "filesystem observation"),
    (".canonicalize()", "filesystem observation"),
    (".read_dir()", "filesystem discovery"),
    ("Instant::now", "clock access"),
    ("SystemTime::now", "clock access"),
];

#[test]
fn core_source_has_no_ambient_capability_calls() {
    let mut pending = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
    let mut failures = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).expect("core source directory is readable") {
            let path = entry.expect("core source entry is readable").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = fs::read_to_string(&path).expect("core source is UTF-8");
                for (forbidden, capability) in FORBIDDEN_SOURCE {
                    if source.contains(forbidden) {
                        failures.push(format!(
                            "{} contains `{forbidden}`, which provides {capability}",
                            path.display()
                        ));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "registry-language-core must depend only on its snapshot:\n{}",
        failures.join("\n")
    );
}

#[test]
fn direct_dependencies_are_the_reviewed_deterministic_set() {
    let manifest = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("core manifest is readable");
    let dependencies = dependency_names(&manifest);
    let permitted = PERMITTED_DEPENDENCIES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(dependencies, permitted);

    let target = "[target.'cfg(target_arch = \"wasm32\")'.dependencies]";
    let random =
        "getrandom_03 = { package = \"getrandom\", version = \"0.3\", features = [\"wasm_js\"] }";
    assert!(manifest.contains(target));
    assert!(manifest.contains(random));
    assert!(
        !rust_sources().iter().any(|source| source.contains("getrandom")),
        "getrandom is permitted only as target compilation plumbing for Rhai; core code must not call it"
    );
}

fn dependency_names(manifest: &str) -> BTreeSet<String> {
    let mut in_runtime_dependencies = false;
    let mut names = BTreeSet::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_runtime_dependencies = line == "[dependencies]"
                || (line.starts_with("[target.") && line.ends_with(".dependencies]"));
        } else if in_runtime_dependencies && !line.is_empty() && !line.starts_with('#') {
            let (name, _) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("unreadable dependency declaration: {line}"));
            names.insert(
                name.trim()
                    .strip_suffix(".workspace")
                    .unwrap_or(name.trim())
                    .to_owned(),
            );
        }
    }
    names
}

fn rust_sources() -> Vec<String> {
    let mut pending = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("core source directory is readable") {
            let path = entry.expect("core source entry is readable").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                sources.push(fs::read_to_string(path).expect("core source is UTF-8"));
            }
        }
    }
    sources
}
