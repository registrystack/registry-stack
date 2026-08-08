//! The crate invariant, checked rather than trusted.
//!
//! `lib.rs` says this crate reads no file, opens no socket, and starts no
//! process. That claim is what lets an editor run these checks against an
//! unsaved buffer, and what keeps the rules usable from a context that has no
//! project directory at all, so it is worth more than a paragraph.
//!
//! Two sweeps hold it. The first reads this crate's own sources and refuses the
//! spellings that would perform input or output. The second reads its manifest
//! and refuses a dependency that could perform input or output on its behalf,
//! because a rule that only searched source text would be satisfied by a crate
//! that called an HTTP client in one line.
//!
//! Neither sweep is a sandbox. `rhai` can read a file when a program it is
//! running imports a module, and it is on this crate never to run one: only
//! `Engine::compile` is called, which parses text and resolves nothing.

use std::{fs, path::PathBuf};

/// Spellings that would take this crate outside its own arguments, each with
/// the reason it is refused.
///
/// `std::path` is deliberately absent: parsing a path is string work, and the
/// authoring form describes files it never opens.
const FORBIDDEN: &[(&str, &str)] = &[
    ("std::fs", "reads or writes a file"),
    ("std::net", "opens a socket"),
    ("std::process", "starts a process"),
    ("std::env", "reads the process environment"),
    ("File::", "opens a file"),
    ("OpenOptions", "opens a file"),
    ("Command::", "starts a process"),
    ("TcpStream", "opens a socket"),
    ("TcpListener", "opens a socket"),
    ("UdpSocket", "opens a socket"),
    ("read_to_string", "reads a file"),
    ("include_str!", "reads a file at build time"),
    ("include_bytes!", "reads a file at build time"),
    ("eval_file", "runs a program from a file"),
    ("compile_file", "reads a program from a file"),
];

/// Every crate this library may link. Each one is a parser, an error type, or
/// a data structure; none of them can reach a file, a socket, or a process on
/// this crate's behalf.
///
/// `url` is on the list because parsing and printing a URL is string work: the
/// authoring form names where a document came from, and never goes there.
const PERMITTED_DEPENDENCIES: &[&str] = &[
    "anyhow",
    "rhai",
    "schemars",
    "serde",
    "serde_json",
    "serde_norway",
    "url",
];

#[test]
fn no_source_file_performs_input_or_output() {
    let sources = rust_sources();
    assert!(
        sources.len() >= 5,
        "the sweep found only {} source files, which is too few to be reading this crate",
        sources.len()
    );
    let mut refusals = Vec::new();
    for path in &sources {
        let text = fs::read_to_string(path).expect("crate sources are readable");
        for (number, line) in text.lines().enumerate() {
            for (spelling, reason) in FORBIDDEN {
                if line.contains(spelling) {
                    let name = path.file_name().expect("named file").to_string_lossy();
                    refusals.push(format!("{name}:{}: `{spelling}` {reason}", number + 1));
                }
            }
        }
    }
    assert!(
        refusals.is_empty(),
        "this crate performs no input or output, but:\n{}",
        refusals.join("\n")
    );
}

#[test]
fn no_dependency_can_perform_input_or_output_on_this_crate_s_behalf() {
    let manifest = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("the manifest is readable");
    let mut declared = Vec::new();
    let mut inside = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == "[dependencies]";
            continue;
        }
        if !inside || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (assigned, _) = line.split_once('=').expect("a dependency line assigns");
        // `name.workspace = true` and `name = { ... }` both name the crate
        // first; the dotted form is the one this workspace writes.
        let name = assigned
            .trim()
            .trim_matches('"')
            .split('.')
            .next()
            .expect("a non-empty dependency name");
        declared.push(name.to_owned());
    }
    assert!(
        !declared.is_empty(),
        "the sweep read no dependencies, so it is not reading the manifest"
    );
    let unexpected = declared
        .iter()
        .filter(|name| !PERMITTED_DEPENDENCIES.contains(&name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        unexpected.is_empty(),
        "these dependencies are not in the permitted set, and this crate's \
         invariant is that none of them can perform input or output: {unexpected:?}"
    );
}

/// Every `.rs` file under this crate's `src`, including nested modules.
fn rust_sources() -> Vec<PathBuf> {
    let mut pending = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).expect("crate directories are readable") {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|value| value == "rs") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    sources
}
