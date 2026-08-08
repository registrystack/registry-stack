//! The crate invariant, checked rather than trusted.
//!
//! `lib.rs` says this crate reads no file, opens no socket, and starts no
//! process. That claim is what lets an editor run these checks against an
//! unsaved buffer, and what keeps the rules usable from a context that has no
//! project directory at all, so it is worth more than a paragraph.
//!
//! Two sweeps hold it. The first reads this crate's own sources and refuses the
//! spellings that would perform input or output, at the call sites as well as
//! in the imports, and it is held to that from both sides: a corpus of hostile
//! source it must refuse, and a corpus of ordinary source it must not, because
//! a sweep that cries wolf is argued down to nothing and a sweep that refuses
//! nothing was never anything. Where those two pull against each other the
//! exceptions are written down by name. The second sweep reads the manifest and
//! refuses a dependency that could perform input or output on this crate's
//! behalf, because a rule that only searched source text would be satisfied by
//! a crate that called an HTTP client in one line.
//!
//! Neither sweep is a sandbox, and the dependency that could read a file on
//! this crate's behalf is `rhai`: an engine straight from `Engine::new` opens
//! whatever path a program's `import` statement names. The engine this crate
//! builds gives that resolver up, so the capability is absent rather than
//! merely unused, and the sweep refuses the entry points that would want it
//! back, including the synonyms of `Engine::new` that would arrive under a name
//! the guard does not read.
//!
//! Reading source is not watching it run, so the last two tests here run the
//! checks against a derivation that imports a module and watch what happens to
//! the module's path. One shows the verdict does not move when the file behind
//! that path does; the other puts a named pipe there, which nothing but an open
//! can wait on, and watches the crate not wait.

use std::{collections::BTreeSet, fs, path::PathBuf};

use registry_evidence_authoring::validate_authored_answer;

/// Spellings that would take this crate outside its own arguments, each with
/// the reason it is refused.
///
/// The list names call sites as well as import paths. An import is the easiest
/// half to write down and the least useful half to catch: `std::fs` is one
/// spelling of a file entry point, `fs::read` is the line that reads the file,
/// and code that does the second without the first is a plain refactor rather
/// than an evasion.
///
/// `std::path` is on the list only where it leaves the string. Joining,
/// splitting and printing a path is string work, and the authoring form
/// describes files it never opens; the methods below are the ones that ask the
/// operating system about a path instead of reading the characters in it.
///
/// The socket types are named one by one rather than by their modules. Both
/// `std::net` and `std::os::unix::net` hold pure value types next to the types
/// that open something, an address is ordinary data this workspace passes
/// around, and a module named whole would refuse the data along with the
/// capability. What opens a socket is a short closed list, so it is written out.
const FORBIDDEN: &[(&str, &str)] = &[
    ("std::fs", "reads or writes a file"),
    ("fs::", "reads or writes a file"),
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
    // Not every socket lives under `std::net`: `std::os::unix::net` is where
    // the Unix domain socket types are, and the Docker socket is a file path.
    ("UnixStream", "opens a socket"),
    ("UnixListener", "opens a socket"),
    ("UnixDatagram", "opens a socket"),
    // The one entry point in `std::net` that reaches the network without
    // naming a socket: resolving a name asks a resolver, over the network.
    ("ToSocketAddrs", "resolves a host name over the network"),
    ("to_socket_addrs", "resolves a host name over the network"),
    // The standard streams. A language server's protocol runs over them, so a
    // line that writes one breaks the conversation this crate is answering
    // inside and a line that reads one takes the questions away.
    ("std::io", "reads or writes a standard stream"),
    ("io::", "reads or writes a standard stream"),
    ("println!", "writes to standard output"),
    ("print!", "writes to standard output"),
    ("eprintln!", "writes to standard error"),
    ("eprint!", "writes to standard error"),
    ("dbg!", "writes to standard error"),
    ("stdin()", "reads standard input"),
    ("stdout()", "writes to standard output"),
    ("stderr()", "writes to standard error"),
    ("read_line", "reads from a stream"),
    ("read_to_end", "reads a stream to its end"),
    ("write_all", "writes to a stream"),
    ("read_to_string", "reads a file"),
    ("read_dir", "lists a directory"),
    // The file system reached through `std::path` rather than `std::fs`. Each
    // of these asks the operating system about a path instead of reading the
    // characters in it, and each is written as a method, so each is written
    // down as one: a bare `exists` is a word that belongs to prose as well.
    (".exists()", "asks whether a path is there"),
    (".try_exists()", "asks whether a path is there"),
    (".is_file()", "asks what a path is"),
    (".is_dir()", "asks what a path is"),
    (".is_symlink()", "asks what a path is"),
    (".metadata()", "stats a file"),
    (".symlink_metadata()", "stats a file without following it"),
    (".canonicalize()", "resolves a path against the file system"),
    (".read_link()", "reads where a link points"),
    ("include_str!", "reads a file at build time"),
    ("include_bytes!", "reads a file at build time"),
    // Code the sweep would otherwise never read. It walks `src`, so a splice
    // and an out-of-tree module are both ways of compiling source it never
    // opens; refusing the two spellings keeps every line it judges the crate's.
    (
        "include!",
        "splices code from a file this sweep never reads",
    ),
    (
        "#[path",
        "compiles a module from a file this sweep never reads",
    ),
    ("eval_file", "runs a program from a file"),
    ("run_file", "runs a program from a file"),
    ("compile_file", "reads a program from a file"),
    // Compiling a program is safe only while it stays compiling. This entry
    // point resolves the program's `import` paths as it parses, so it reads a
    // file for every module the author named.
    (
        "compile_into_self_contained",
        "resolves an imported module, which reads a file",
    ),
    (
        "FileModuleResolver",
        "resolves an imported module by reading a file",
    ),
    // Every other way of getting an engine. `Engine::default` is `Engine::new`
    // (rhai 1.25.1, `src/engine.rs`), so it arrives carrying the file-reading
    // resolver under a name the guard below does not read; the raw pair arrives
    // without one, which is safe but equally unread. Leaving one spelling is
    // what lets the guard speak for every engine this crate builds.
    ("Engine::default", "builds an engine the guard cannot read"),
    ("Engine::new_raw", "builds an engine the guard cannot read"),
    ("Engine::RAW", "builds an engine the guard cannot read"),
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

/// Longer spellings that hold a forbidden one inside them and reach nothing,
/// each with what it actually names.
///
/// The forbidden list is written short on purpose, so that a module is refused
/// whatever is taken out of it, and a type is refused whoever re-exports it.
/// Written that short it also catches three names that reach nothing: two the
/// compiler resolves without asking anyone, and one that belongs to `clap`
/// rather than to `std::process`. All three are ordinary in the crates next
/// door. Naming them costs three lines and keeps the short entries; widening
/// the short entries to make room for them would cost `env::var` and
/// `process::Command`, which is the wrong trade.
///
/// An exception is a spelling, not a prefix: it is read as a whole segment on
/// both sides, so a longer name that merely starts the same way stays refused.
const NOT_ENTRY_POINTS: &[(&str, &str)] = &[
    (
        "env::consts",
        "compile-time constants, resolved without asking anything",
    ),
    ("process::ExitCode", "a return type, which starts nothing"),
    (
        "clap::Command",
        "a command line, which is parsed rather than run",
    ),
];

/// One spelling the source sweep refuses, and the line it was found on.
struct Refusal {
    line: usize,
    spelling: &'static str,
    reason: &'static str,
}

/// Whether a character belongs to a name rather than separating two of them.
fn inside_a_name(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// Every offset at which a stretch of text names a spelling as a segment of its
/// own rather than as the tail of a longer name.
///
/// The boundary earns its place on one collision: this crate has a
/// `ProjectFile` type, so a plain substring search for `File::` refuses an
/// ordinary `ProjectFile::` call, and a sweep that cries wolf gets widened
/// until it means nothing. A spelling that already begins on a separator, such
/// as `.exists()`, carries its own left boundary and is searched for as
/// written.
///
/// Only the left side is bounded. A forbidden spelling is written as the head
/// of the path it forbids, so `std::fs` has to go on matching `std::fs::read`
/// and `fs::` has to go on matching `fs::write`.
fn named_at(text: &str, spelling: &str) -> Vec<usize> {
    text.match_indices(spelling)
        .filter(|(at, _)| {
            !spelling.starts_with(inside_a_name) || !text[..*at].ends_with(inside_a_name)
        })
        .map(|(at, _)| at)
        .collect()
}

/// Whether a stretch of text names a spelling as a segment of its own.
fn names(text: &str, spelling: &str) -> bool {
    !named_at(text, spelling).is_empty()
}

/// The same stretch of text with every name that opens nothing blanked out.
///
/// Blanking rather than exempting the whole line is what keeps an exception
/// local: `use std::env::{consts, var};` loses neither `std::env` nor its
/// refusal, because the text it holds is not the text `env::consts`. The blank
/// is written as spaces so that the characters either side of it stay apart
/// and cannot be read as one name.
///
/// An exception is bounded on both sides. Unlike a forbidden spelling it stands
/// for the whole name and not for the head of a longer one, so
/// `process::ExitCoder` is left alone for the forbidden list to refuse.
fn without_the_names_that_open_nothing(text: &str) -> String {
    let mut readable = text.to_owned();
    for &(spelling, _) in NOT_ENTRY_POINTS {
        let found = named_at(&readable, spelling)
            .into_iter()
            .filter(|at| !readable[at + spelling.len()..].starts_with(inside_a_name))
            .collect::<Vec<_>>();
        for at in found {
            readable.replace_range(at..at + spelling.len(), &" ".repeat(spelling.len()));
        }
    }
    readable
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
        let candidate = without_the_names_that_open_nothing(&candidate);
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
///
/// The standard streams are here for a reason of their own. This crate is
/// linked into a language server that speaks JSON-RPC over them, so a line that
/// prints corrupts the protocol its host is holding a conversation on and a
/// line that reads takes the request stream away from it. Neither shows up as
/// an editor reading a file; both show up as an editor that has stopped
/// answering.
///
/// The path lines are the file system reached without naming `std::fs`. Asking
/// whether a path is there is a system call, not string work, and the first of
/// them is the likeliest refactor there is: walking up from a document to find
/// the project root, in a crate whose point is working without one.
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
use std::net::ToSocketAddrs;
let peers = "registry.internal:443".to_socket_addrs().unwrap();
let stream = std::net::TcpStream::connect(peers.last().unwrap()).unwrap();
use std::env::{consts, var};
let child = std::process::Command::new("sh").spawn().unwrap();
println!("{question:?}");
print!("{answer}");
eprintln!("authoring: {message}");
eprint!("{answer}");
dbg!(&question);
use std::io::{BufRead, Read, Write};
let handle = stdin();
handle.read_line(&mut line).unwrap();
stdout().write_all(line.as_bytes()).unwrap();
writeln!(stderr().lock(), "{line}").unwrap();
io::copy(&mut source, &mut sink).unwrap();
reader.read_to_end(&mut bytes).unwrap();
let root = path.ancestors().find(|step| step.join(".evidence").exists());
if !path.try_exists().unwrap_or(false) { return; }
if path.is_file() { return; }
if path.is_dir() { return; }
if path.is_symlink() { return; }
let stamp = path.metadata().unwrap().modified().unwrap();
let link = path.symlink_metadata().unwrap();
let real = path.canonicalize().unwrap();
let target = path.read_link().unwrap();
include!("../../shared/io_helpers.rs");
#[path = "../../shared/io_helpers.rs"]
let engine = rhai::Engine::default();
let engine = rhai::Engine::new_raw();
let engine = rhai::Engine::RAW;
"#;

/// Ordinary lines lifted from this crate's own sources, so that the sweep is
/// measured against real work as well as against hostile work. A sweep that
/// refuses everything says as little as one that refuses nothing, and this
/// corpus is what keeps the first from being mistaken for rigour.
///
/// The last five lines come from elsewhere in this workspace rather than from
/// this crate, because the spellings that cost a sweep its readers are the ones
/// a neighbouring crate writes every day: an IP address is a value type, the
/// platform constants are resolved by the compiler, an exit code is a return
/// type, and `clap` names its builder after the thing this crate must not
/// start. None of them opens anything, and a sweep that refused them would be
/// argued down to nothing the first time somebody moved code in here.
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
use rhai::module_resolvers::DummyModuleResolver;
engine.set_module_resolver(DummyModuleResolver::new());
let Ok(ast) = parser().compile(source) else {
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
Some(Host::Ipv6(address)) if address == std::net::Ipv6Addr::LOCALHOST => {}
match (std::env::consts::OS, std::env::consts::ARCH) {
use std::process::ExitCode;
let command = clap::Command::new("evidencectl");
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
    // still `std::fs` and `std::io`, but no single line of it says either.
    let wrapped = "use std::{\n    io::Write,\n    fs,\n};\n";
    let refused = refusals(wrapped)
        .iter()
        .map(|refusal| refusal.spelling)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        refused,
        BTreeSet::from(["std::fs", "std::io", "io::"]),
        "the sweep read {wrapped:?} as clean"
    );
}

/// `rhai::Engine::new()` installs a module resolver that reads files: with the
/// default features this workspace pins, that is a `FileModuleResolver`, and it
/// opens whatever path an `import` statement names. Nothing in this crate asks
/// for a module today, but "nothing asks for it" is a fact about one call site
/// rather than a property of the engine, and one call changed from `compile` to
/// `compile_into_self_contained` would turn an editor into a file reader driven
/// by an author's own text.
///
/// So the engine is built without that capability rather than merely never
/// using it, and any engine this crate builds later has to disarm itself the
/// same way.
///
/// `Engine::new(` is the only construction spelling the forbidden list leaves,
/// so counting it counts the engines. The count is a bound rather than a proof:
/// nothing here follows a value from where it is built to where it is disarmed,
/// so a file that disarmed one engine twice and left a second alone would
/// satisfy it. What it does hold is the shape a second engine actually arrives
/// in, which is a second call site next to a first that already disarms.
fn disarms_every_engine(text: &str) -> bool {
    named_at(text, "set_module_resolver").len() >= named_at(text, "Engine::new(").len()
}

#[test]
fn every_rhai_engine_this_crate_builds_gives_up_its_module_resolver() {
    let armed = rust_sources()
        .into_iter()
        .filter(|path| {
            let text = fs::read_to_string(path).expect("crate sources are readable");
            !disarms_every_engine(&text)
        })
        .map(|path| {
            path.file_name()
                .expect("named file")
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert!(
        armed.is_empty(),
        "these sources build a rhai engine and leave its file-reading module \
         resolver in place: {armed:?}"
    );
}

#[test]
fn the_engine_guard_reads_every_engine_a_file_builds() {
    let disarmed = "fn parser() -> Engine {\n    let mut engine = Engine::new();\n\
                    \n    engine.set_module_resolver(DummyModuleResolver::new());\n\
                    \n    engine\n}\n";
    assert!(disarms_every_engine(disarmed));
    // A second call site, added the way a second call site gets added: the
    // first engine is still disarmed, and the file still says so, so a guard
    // that asks whether the file mentions disarming at all reads this as clean.
    let second = format!("{disarmed}\nfn schema_parser() -> Engine {{\n    Engine::new()\n}}\n");
    assert!(!disarms_every_engine(&second));
    // The synonym this guard cannot see, and the division of labour that makes
    // that all right: counting cannot tell `Engine::default` from no engine at
    // all, so the forbidden list is what leaves one construction spelling for
    // the counting to be about.
    let synonym = "fn parser() -> Engine {\n    Engine::default()\n}\n";
    assert!(disarms_every_engine(synonym));
    assert!(!refusals(synonym).is_empty());
}

/// A directory of this test's own, under the system temporary directory.
///
/// Files on disk are what make "the file was not read" observable, and they
/// have to be written from here: the crate under test is the one thing in this
/// package that may not write them.
fn scratch_directory(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "registry-evidence-authoring-{}-{name}",
        std::process::id()
    ));
    if directory.exists() {
        fs::remove_dir_all(&directory).expect("a leftover scratch directory is removable");
    }
    fs::create_dir_all(&directory).expect("a writable temporary directory");
    directory
}

/// An authored derivation may say `import`, and an editor runs these checks
/// over whatever an author has typed, unsaved and unreviewed. Reading such a
/// program must not read the files the program names.
///
/// The first half of this test shows the hazard is real rather than
/// theoretical: an engine built the ordinary way decides what to return from
/// what is on disk, and says so three different ways for a module that parses,
/// one that does not, and one that is not there. The second half shows that
/// this crate's verdict does not move when the disk does, which it could not
/// claim if it had opened any of them.
#[test]
fn an_authored_import_does_not_read_the_file_it_names() {
    let directory = scratch_directory("authored-import");
    let parsable = directory.join("parsable");
    fs::write(parsable.with_extension("rhai"), "let observed = 1;\n")
        .expect("the scratch directory is writable");
    let unparsable = directory.join("unparsable");
    fs::write(unparsable.with_extension("rhai"), "!! not a program !!\n")
        .expect("the scratch directory is writable");
    let absent = directory.join("absent");

    let program = |module: &PathBuf| {
        format!(
            "import \"{}\" as imported;\nfn answer(facts, selectors, context) {{ #{{}} }}\n",
            module.display()
        )
    };
    let engine = rhai::Engine::new();
    let scope = rhai::Scope::new();
    let resolved = |module| engine.compile_into_self_contained(&scope, program(module));
    assert!(resolved(&parsable).is_ok());
    assert!(resolved(&unparsable).is_err());
    assert!(resolved(&absent).is_err());

    for module in [&parsable, &unparsable, &absent] {
        assert_eq!(
            validate_authored_answer(&program(module)),
            Vec::new(),
            "reading a derivation that imports `{}` reported something, so \
             something read the path",
            module.display()
        );
    }

    fs::remove_dir_all(&directory).expect("the scratch directory is removable");
}

/// Whether a piece of work finishes inside a deadline.
///
/// The work runs on a thread of its own, so work that never finishes stops this
/// suite waiting rather than stopping this suite. A thread left blocked in
/// `open` cannot be woken from here and is not joined: it holds one descriptor
/// on a file in a scratch directory, and it goes when the test binary does.
#[cfg(unix)]
fn finishes_within(deadline: std::time::Duration, work: impl FnOnce() + Send + 'static) -> bool {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        work();
        // Past the deadline the receiver is gone. That is the answer this
        // function returns, not a failure to report.
        let _ = done.send(());
    });
    finished.recv_timeout(deadline).is_ok()
}

/// The same claim as above, observed at the system call rather than at the
/// verdict.
///
/// A verdict that does not move says the contents were not used. It does not
/// say the path was not opened, and an editor that opens whatever an author
/// types is the hazard whether or not it keeps what it finds. A named pipe
/// tells the two apart: opening one for reading blocks until a writer arrives,
/// so a reader hangs where a non-reader returns and the answer is a duration.
///
/// Both halves run behind a deadline, so this test can fail but cannot hang.
/// The two waits are deliberately lopsided. The armed engine is blocked in
/// `open` and is never coming back, so a short wait settles it; the crate under
/// test answers in microseconds and is given long enough that a loaded machine
/// cannot be mistaken for a blocked one.
///
/// Named pipes are a Unix idea, so this runs on the two platforms CI uses and
/// the verdict test above is what runs everywhere.
#[cfg(unix)]
#[test]
fn reading_an_authored_import_never_opens_the_path_it_names() {
    use std::{os::unix::fs::FileTypeExt, time::Duration};

    let directory = scratch_directory("named-pipe");
    let module = directory.join("blocking");
    let pipe = module.with_extension("rhai");
    let made = std::process::Command::new("mkfifo")
        .arg(&pipe)
        .status()
        .expect("mkfifo is runnable");
    assert!(made.success(), "mkfifo left no pipe at {}", pipe.display());
    assert!(
        fs::symlink_metadata(&pipe)
            .expect("the pipe is there")
            .file_type()
            .is_fifo(),
        "{} is not a named pipe, so blocking would mean nothing",
        pipe.display()
    );

    let program = format!(
        "import \"{}\" as imported;\nfn answer(facts, selectors, context) {{ #{{}} }}\n",
        module.display()
    );

    // The control. A probe that cannot tell a reader from a non-reader says
    // nothing about either, so the reader is run first and has to hang.
    let armed = {
        let program = program.clone();
        finishes_within(Duration::from_secs(2), move || {
            let engine = rhai::Engine::new();
            // The verdict is not what is being read here; the duration is.
            let _ = engine.compile_into_self_contained(&rhai::Scope::new(), program);
        })
    };
    assert!(
        !armed,
        "an engine carrying rhai's own module resolver returned without \
         blocking on {}, so this probe proves nothing and needs rewriting",
        pipe.display()
    );

    let subject = finishes_within(Duration::from_secs(30), move || {
        let _ = validate_authored_answer(&program);
    });
    assert!(
        subject,
        "reading a derivation that imports `{}` blocked, which is what opening \
         a named pipe with no writer does",
        pipe.display()
    );

    fs::remove_dir_all(&directory).expect("the scratch directory is removable");
}

#[test]
fn the_source_sweep_reads_a_forbidden_spelling_as_a_whole_segment() {
    assert!(!refusals("let handle = File::open(path)?;").is_empty());
    // The collision the boundary rule exists for. `ProjectFile` is this
    // crate's own type and ends in the name of the one it must not open.
    assert!(refusals("let first = ProjectFile::from(&files[0]);").is_empty());
}

/// The exceptions are the only place this sweep says yes, so where they stop is
/// worth pinning next to what they cover.
#[test]
fn the_source_sweep_lets_a_name_that_opens_nothing_through_without_its_module() {
    // Resolved by the compiler, and the reason the exception is written down.
    assert!(refusals("match (std::env::consts::OS, std::env::consts::ARCH) {").is_empty());
    // Standing beside an exempt name saves nothing: this import is still the
    // one that brings `env::var` into scope.
    assert!(!refusals("use std::env::{consts, var};").is_empty());
    // An exception is a whole name rather than a prefix. No such type exists;
    // what is pinned is that the sweep does not stop at the characters it
    // recognises and call the rest of the name exempt.
    assert!(!refusals("let code = process::ExitCoder::from(status);").is_empty());
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
///
/// One line declares one crate. A key line that assigns nothing, or one whose
/// value opens an inline table it does not close, stops the sweep rather than
/// being read as far as it goes: a wrapped table read a line at a time turns
/// `features = [` into a crate called `features` and a git revision into a
/// crate called `rev`, and the sweep would rather say it cannot read the
/// manifest than answer with names nobody wrote.
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
        let unreadable = format!(
            "`{line}` declares a dependency in a shape this sweep does not read: \
             teach it the shape rather than reading part of a line as a crate name"
        );
        let Some((assigned, value)) = line.split_once('=') else {
            panic!("{unreadable}");
        };
        assert_eq!(
            value.matches('{').count(),
            value.matches('}').count(),
            "{unreadable}"
        );
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
fn the_dependency_sweep_refuses_an_inline_table_wrapped_over_several_lines() {
    // What rustfmt leaves once an inline table is long enough. A line at a
    // time, the middle of this declares a crate called `features` and the end
    // of it declares nothing at all.
    declared_dependencies(
        "[dependencies]\nrhai = { workspace = true, features = [\n    \"sync\",\n] }\n",
    );
}

#[test]
#[should_panic(expected = "a shape this sweep does not read")]
fn the_dependency_sweep_refuses_a_git_source_wrapped_over_several_lines() {
    // A line at a time, the second line of this declares a crate called `rev`.
    // It would be reported as a dependency outside the permitted set, which is
    // the right verdict reached by reading a revision as a crate name.
    declared_dependencies(
        "[dependencies]\ncrosswalk = { git = \"https://example.invalid/crosswalk\",\n\
         \n    rev = \"0000000\" }\n",
    );
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
