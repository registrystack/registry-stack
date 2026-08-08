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

/// What a manifest section header means to the dependency sweep.
enum Table {
    /// Not a table that adds a crate to a normal build.
    Unrelated,
    /// A table whose key lines each name a dependency.
    Keys,
    /// A sub-table whose header names the one dependency it configures.
    Named(String),
}

/// Read a section header as the dependency table it is, if it is one.
///
/// Cargo gives a dependency table two placements, `[dependencies]` and
/// `[target.<cfg>.dependencies]`, and either may be followed by the name of the
/// one crate a sub-table configures. All four spellings link a crate into this
/// library, so all four are swept. `dev-dependencies` and `build-dependencies`
/// are not: the invariant is about what this crate links into a caller, and
/// neither a test binary nor a build script is that.
///
/// A header that mentions dependencies in some other shape stops the sweep
/// rather than being skipped, because a sweep that passes over what it cannot
/// read is how a dependency gets in unnoticed.
fn dependency_table(header: &str) -> Table {
    const KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
    let unreadable = format!(
        "`[{header}]` names a dependency table in a shape this sweep does not read: \
         teach it the shape rather than letting the table through unswept"
    );
    let segments = header_segments(header);
    let Some(kind) = segments
        .iter()
        .position(|segment| KINDS.contains(&segment.as_str()))
    else {
        assert!(!header.contains("dependencies"), "{unreadable}");
        return Table::Unrelated;
    };
    assert!(
        (kind == 0 || (kind == 2 && segments[0] == "target")) && segments.len() - kind <= 2,
        "{unreadable}"
    );
    if segments[kind] != "dependencies" {
        return Table::Unrelated;
    }
    match segments.get(kind + 1) {
        None => Table::Keys,
        Some(name) => Table::Named(name.trim_matches(['\'', '"']).to_owned()),
    }
}

/// A dotted manifest header split on its separators, leaving a quoted segment
/// such as `'cfg(target_os = "wasi")'` whole even where it holds a dot.
fn header_segments(header: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for character in header.chars() {
        if let Some(open) = quote {
            current.push(character);
            if character == open {
                quote = None;
            }
        } else if character == '\'' || character == '"' {
            current.push(character);
            quote = Some(character);
        } else if character == '.' {
            segments.push(current.trim().to_owned());
            current.clear();
        } else {
            current.push(character);
        }
    }
    segments.push(current.trim().to_owned());
    segments
}

/// The crates a manifest adds to a normal build of this package.
fn declared_dependencies(manifest: &str) -> Vec<String> {
    let mut declared = Vec::new();
    let mut inside = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            let header = line.trim_matches(['[', ']']);
            inside = false;
            match dependency_table(header) {
                Table::Unrelated => {}
                Table::Keys => inside = true,
                Table::Named(name) => declared.push(name),
            }
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
    declared
}

#[test]
fn the_dependency_sweep_reads_a_platform_specific_table() {
    assert_eq!(
        declared_dependencies(
            "[dependencies]\nserde.workspace = true\n\
             \n[target.'cfg(unix)'.dependencies]\nrustix = { workspace = true }\n"
        ),
        vec!["serde".to_owned(), "rustix".to_owned()]
    );
}

#[test]
fn the_dependency_sweep_reads_a_sub_table_header_as_a_declaration() {
    assert_eq!(
        declared_dependencies("[dependencies.reqwest]\nversion = \"0.12\"\n"),
        vec!["reqwest".to_owned()]
    );
}

#[test]
fn the_dependency_sweep_leaves_test_and_build_only_tables_alone() {
    // The invariant is about what this crate links into a caller. A test binary
    // and a build script are neither, so a dependency of one does not break it.
    let manifest = "[dev-dependencies]\njsonschema.workspace = true\n\
                    \n[dev-dependencies.tokio]\nversion = \"1\"\n\
                    \n[build-dependencies]\ncc = \"1\"\n\
                    \n[target.'cfg(unix)'.dev-dependencies]\nrustix = \"1\"\n";
    assert!(declared_dependencies(manifest).is_empty());
}

#[test]
#[should_panic(expected = "a shape this sweep does not read")]
fn the_dependency_sweep_refuses_a_dependency_table_in_an_unfamiliar_place() {
    declared_dependencies("[workspace.dependencies]\nserde = \"1\"\n");
}

#[test]
#[should_panic(expected = "a shape this sweep does not read")]
fn the_dependency_sweep_refuses_a_header_it_cannot_split_into_segments() {
    // Legal TOML the sweep has not been taught, so it stops rather than reading
    // the table as unrelated and letting every key line under it through.
    declared_dependencies("[dependencies] # the crates this library links\nurl = \"2\"\n");
}

#[test]
fn the_dependency_sweep_ignores_tables_that_declare_nothing() {
    let manifest = "[package]\nname = \"registry-evidence-authoring\"\n\
                    \n[[example]]\nname = \"authoring-schema\"\n\
                    \n[features]\nschema = [\"dep:schemars\"]\n";
    assert!(declared_dependencies(manifest).is_empty());
}

#[test]
fn no_dependency_can_perform_input_or_output_on_this_crate_s_behalf() {
    let manifest = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("the manifest is readable");
    let declared = declared_dependencies(&manifest);
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
