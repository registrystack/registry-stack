//! The crate invariant, checked rather than trusted.
//!
//! `lib.rs` says this crate reads no file, opens no socket, and starts no
//! process. That claim is what lets an editor run these checks against an
//! unsaved buffer, and what keeps the rules usable from a context that has no
//! project directory at all, so it is worth more than a paragraph.
//!
//! Two sweeps hold it. The first reads this crate's own sources and refuses the
//! spellings that would perform input or output, at the call sites as well as
//! in the imports, and it is held to that by a corpus of hostile source it must
//! refuse and a corpus of ordinary source it must not. The second reads its
//! manifest and refuses a dependency that could perform input or output on its
//! behalf, because a rule that only searched source text would be satisfied by
//! a crate that called an HTTP client in one line.
//!
//! Neither sweep is a sandbox. `rhai` can read a file when a program it is
//! running imports a module, and it is on this crate never to run one: only
//! `Engine::compile` is called, which parses text and resolves nothing.

use std::{collections::BTreeSet, fs, path::PathBuf};

/// Spellings that would take this crate outside its own arguments, each with
/// the reason it is refused.
///
/// The list names call sites as well as import paths. An import is the easiest
/// half to write down and the least useful half to catch: `std::fs` is one
/// spelling of a file entry point, `fs::read` is the line that reads the file,
/// and code that does the second without the first is a plain refactor rather
/// than an evasion.
///
/// `std::path` is deliberately absent: parsing a path is string work, and the
/// authoring form describes files it never opens.
const FORBIDDEN: &[(&str, &str)] = &[
    ("std::fs", "reads or writes a file"),
    ("fs::", "reads or writes a file"),
    ("std::net", "opens a socket"),
    // Not every socket lives under `std::net`: `std::os::unix::net` is where
    // the Unix domain socket types are, and the Docker socket is a file path.
    ("::net", "opens a socket"),
    ("std::process", "starts a process"),
    ("process::", "starts a process"),
    ("std::env", "reads the process environment"),
    ("env::", "reads the process environment"),
    ("File::", "opens a file"),
    ("OpenOptions", "opens a file"),
    ("Command::", "starts a process"),
    ("TcpStream", "opens a socket"),
    ("TcpListener", "opens a socket"),
    ("UdpSocket", "opens a socket"),
    ("UnixStream", "opens a socket"),
    ("UnixListener", "opens a socket"),
    ("UnixDatagram", "opens a socket"),
    ("read_to_string", "reads a file"),
    ("read_dir", "lists a directory"),
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

/// One spelling the source sweep refuses, and the line it was found on.
struct Refusal {
    line: usize,
    spelling: &'static str,
    reason: &'static str,
}

/// Whether a stretch of text names a forbidden spelling as a segment of its
/// own rather than as the tail of a longer name.
///
/// The boundary earns its place on one collision: this crate has a
/// `ProjectFile` type, so a plain substring search for `File::` refuses an
/// ordinary `ProjectFile::` call, and a sweep that cries wolf gets widened
/// until it means nothing. A spelling that already begins on a separator, such
/// as `::net`, carries its own left boundary and is searched for as written.
fn names(text: &str, spelling: &str) -> bool {
    let inside_a_name = |character: char| character.is_alphanumeric() || character == '_';
    if !spelling.starts_with(inside_a_name) {
        return text.contains(spelling);
    }
    text.match_indices(spelling)
        .any(|(at, _)| !text[..at].ends_with(inside_a_name))
}

/// Every refusal a stretch of Rust earns.
///
/// Two readings are needed. Reading line by line catches the call sites, which
/// is where the input or output actually happens. Reading each `use` as a
/// whole statement catches the import whatever shape it is written in: a
/// grouped import is how this workspace normally writes its imports, and
/// neither `use std::{fs, path::Path};` nor the line `fs,` left behind once
/// rustfmt has split that group over several lines holds the spelling
/// `std::fs` anywhere in it.
fn refusals(text: &str) -> Vec<Refusal> {
    let mut candidates = text
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.to_owned()))
        .collect::<Vec<_>>();
    candidates.extend(imported_paths(text));
    let mut found = Vec::new();
    for (line, candidate) in candidates {
        for &(spelling, reason) in FORBIDDEN {
            if names(&candidate, spelling) {
                found.push(Refusal {
                    line,
                    spelling,
                    reason,
                });
            }
        }
    }
    found
}

/// Whether a line opens a `use` statement, under any visibility.
fn opens_an_import(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("use ") || (trimmed.starts_with("pub") && trimmed.contains(" use "))
}

/// Every path a file's `use` statements bring into scope, paired with the line
/// its statement started on.
///
/// A statement is read to its semicolon rather than to the end of its first
/// line, and its whitespace is dropped, so that a wrapped import reads the same
/// as a single-line one. What comes back is one flat path per imported name,
/// with the keyword and the visibility in front of it left off: a path is what
/// the forbidden spellings are written as, and `usestd::fs` would read as a
/// longer name rather than as the entry point it is.
fn imported_paths(text: &str) -> Vec<(usize, String)> {
    let mut paths = Vec::new();
    let mut lines = text.lines().enumerate();
    while let Some((index, line)) = lines.next() {
        if !opens_an_import(line) {
            continue;
        }
        let mut statement = line
            .split_whitespace()
            .skip_while(|token| *token != "use")
            .skip(1)
            .collect::<String>();
        while !statement.contains(';') {
            let Some((_, continuation)) = lines.next() else {
                break;
            };
            statement.extend(continuation.split_whitespace());
        }
        paths.extend(
            expand_groups(&statement)
                .into_iter()
                .map(|path| (index + 1, path)),
        );
    }
    paths
}

/// One string per path a grouped import stands for: `a::{b, c::{d, e}}` comes
/// back as `a::b`, `a::c::d` and `a::c::e`.
///
/// A group this cannot read, such as one whose braces never close, comes back
/// as written rather than being dropped, because the line-by-line reading still
/// has to see it.
fn expand_groups(statement: &str) -> Vec<String> {
    let Some(open) = statement.find('{') else {
        return vec![statement.to_owned()];
    };
    let Some(close) = closing_brace(statement, open) else {
        return vec![statement.to_owned()];
    };
    let (prefix, suffix) = (&statement[..open], &statement[close + 1..]);
    let mut paths = Vec::new();
    for entry in group_entries(&statement[open + 1..close]) {
        paths.extend(expand_groups(&format!("{prefix}{entry}{suffix}")));
    }
    paths
}

/// Where the brace opened at `open` closes, if it closes at all.
fn closing_brace(statement: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, character) in statement.char_indices().skip(open) {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// The entries of one import group, split on the commas that belong to it
/// rather than on the commas of a group nested inside it.
fn group_entries(inside: &str) -> Vec<&str> {
    let mut entries = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (at, character) in inside.char_indices() {
        match character {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                entries.push(&inside[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    entries.push(&inside[start..]);
    entries.retain(|entry| !entry.is_empty());
    entries
}

#[test]
fn no_source_file_performs_input_or_output() {
    let sources = rust_sources();
    assert!(
        sources.len() >= 5,
        "the sweep found only {} source files, which is too few to be reading this crate",
        sources.len()
    );
    let mut reported = Vec::new();
    for path in &sources {
        let text = fs::read_to_string(path).expect("crate sources are readable");
        let name = path.file_name().expect("named file").to_string_lossy();
        for refusal in refusals(&text) {
            reported.push(format!(
                "{name}:{}: `{}` {}",
                refusal.line, refusal.spelling, refusal.reason
            ));
        }
    }
    assert!(
        reported.is_empty(),
        "this crate performs no input or output, but:\n{}",
        reported.join("\n")
    );
}

/// Hostile Rust that no reviewer would call exotic, held here as text rather
/// than as a file on disk or as compiled code, because reading source text is
/// what the sweep does and this is source it must refuse.
///
/// Between them these lines read `/etc/passwd`, write a file, list a home
/// directory, take a secret out of the environment and open the Docker socket,
/// and every one of them is spelled the way an ordinary refactor spells it:
/// grouped imports, call sites rather than import paths, and the Unix socket
/// types that live outside `std::net`.
const HOSTILE_SOURCE: &str = r#"use std::{fs, path::Path};
let bytes = fs::read(Path::new("/etc/passwd")).unwrap();
fs::write("/tmp/exfil", bytes).unwrap();
for e in fs::read_dir("/Users").unwrap() { let _ = e; }
use std::{env};
let token = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
use std::os::unix::net::UnixStream;
let sock = UnixStream::connect("/var/run/docker.sock").unwrap();
use std::{process};
process::exit(1);
"#;

/// Ordinary lines lifted from this crate's own sources, so that the sweep is
/// measured against real work as well as against hostile work. A sweep that
/// refuses everything says as little as one that refuses nothing, and this
/// corpus is what keeps the first from being mistaken for rigour.
const ORDINARY_SOURCE: &str = r#"use std::{
    collections::BTreeSet,
    path::{Component, Path},
};
use std::{collections::BTreeMap, path::PathBuf};
use std::fmt::{self, Display, Formatter};
use super::{compact_form_project, referenced_form_project, ProjectFile};
use serde_json::{Map as JsonMap, Value};
let path = Path::new(value);
assert!(files.contains(&ProjectFile {
    path: "questions/sample-question.yaml".to_owned(),
    contents: "question-body".to_owned(),
}));
let Ok(ast) = rhai::Engine::new().compile(source) else {
"#;

#[test]
fn the_source_sweep_refuses_every_line_of_a_hostile_corpus() {
    let refused = refusals(HOSTILE_SOURCE)
        .iter()
        .map(|refusal| refusal.line)
        .collect::<BTreeSet<_>>();
    let missed = HOSTILE_SOURCE
        .lines()
        .enumerate()
        .filter(|(index, _)| !refused.contains(&(index + 1)))
        .map(|(index, line)| format!("{}: {line}", index + 1))
        .collect::<Vec<_>>();
    assert!(
        missed.is_empty(),
        "the sweep let hostile source through:\n{}",
        missed.join("\n")
    );
}

#[test]
fn the_source_sweep_refuses_nothing_in_an_ordinary_corpus() {
    let reported = refusals(ORDINARY_SOURCE)
        .iter()
        .map(|refusal| {
            format!(
                "{}: `{}` {}",
                refusal.line, refusal.spelling, refusal.reason
            )
        })
        .collect::<Vec<_>>();
    assert!(
        reported.is_empty(),
        "the sweep refused ordinary source, which is how a sweep stops being read:\n{}",
        reported.join("\n")
    );
}

#[test]
fn the_source_sweep_reads_an_import_however_it_is_wrapped() {
    // What rustfmt does to a group once it is long enough: the import is
    // still `std::fs`, but no single line of it says so.
    let wrapped = "use std::{\n    io::Write,\n    fs,\n};\n";
    let refused = refusals(wrapped)
        .iter()
        .map(|refusal| refusal.spelling)
        .collect::<Vec<_>>();
    assert_eq!(refused, ["std::fs"], "the sweep read {wrapped:?} as clean");
}

#[test]
fn the_source_sweep_reads_a_forbidden_spelling_as_a_whole_segment() {
    assert!(!refusals("let handle = File::open(path)?;").is_empty());
    // The collision the boundary rule exists for. `ProjectFile` is this
    // crate's own type and ends in the name of the one it must not open.
    assert!(refusals("let first = ProjectFile::from(&files[0]);").is_empty());
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
