// SPDX-License-Identifier: Apache-2.0
//! The offline check of a runtime file (CFG-CHECK-1): the file read as the
//! runtime reads it, with no secret material and, unless asked, no process
//! environment.

use std::collections::BTreeMap;
use std::path::Path;

use registry_platform_yaml::{escape_pointer_segment, Diagnostic, Node, NodeValue, Reader, Source};
use serde::de::DeserializeOwned;

use crate::{
    contains_environment_expression, LoadedRuntimeConfig, RuntimeConfigLoader, UNAVAILABLE_CODE,
};

/// The stand-in for a deferred expression whose member names no other.
pub const DEFAULT_STAND_IN: &str = "deferred";

/// The code of the warning that a check without the environment stopped at a
/// member holding an expression, and did not read the members after it.
pub const INCOMPLETE_CODE: &str = "platform.runtime-config.check-incomplete";

/// What an offline check of one runtime file found.
#[derive(Debug)]
pub struct RuntimeFileCheck<T> {
    /// The decoded configuration, when the loader accepted the file. A
    /// member that holds a deferred expression carries its stand-in.
    pub loaded: Option<LoadedRuntimeConfig<T>>,
    /// Every loader finding, each naming the file as the path was given. A
    /// finding that depends on the value of a deferred expression is left
    /// out; in its place stands a warning, coded [`INCOMPLETE_CODE`], that
    /// the check stopped at that member.
    pub diagnostics: Vec<Diagnostic>,
    /// The file could not be read at all, as opposed to read and refused.
    pub unavailable: bool,
    file: String,
    tree: Option<Node>,
    deferred: Deferred,
}

impl<T> RuntimeFileCheck<T> {
    /// Whether the member at `pointer`, or a member above it, holds an
    /// expression the check did not substitute. A product skips its value
    /// checks of such a member.
    #[must_use]
    pub fn defers(&self, pointer: &str) -> bool {
        self.deferred.covers(pointer)
    }

    /// Whether a member at, above, or below `pointer` holds an expression
    /// the check did not substitute. A product skips a check that reads
    /// every member of a list or mapping when one of them is deferred.
    #[must_use]
    pub fn defers_within(&self, pointer: &str) -> bool {
        self.deferred.covers(pointer) || self.deferred.lies_below(pointer)
    }

    /// An error positioned at the value of the member at `pointer`, naming
    /// the file as the path was given and `artifact` as the document kind.
    #[must_use]
    pub fn error_at(
        &self,
        artifact: &str,
        code: &str,
        pointer: &str,
        message: impl Into<String>,
        suggested_action: impl Into<String>,
    ) -> Diagnostic {
        let mut diagnostic = Diagnostic::error(code, pointer, message, suggested_action);
        diagnostic.artifact = Some(artifact.to_owned());
        let position = self
            .tree
            .as_ref()
            .and_then(|root| root.pointer(pointer))
            .map(|node| node.span.start);
        diagnostic.source = Some(Source {
            file: self.file.clone(),
            line: position.map(|position| position.line),
            column: position.map(|position| position.column),
        });
        diagnostic
    }
}

impl RuntimeConfigLoader {
    /// Check the runtime file at the absolute `path` as the runtime reads it,
    /// with no secret material (CFG-CHECK-1).
    ///
    /// With `substitute` set, `${NAME}` expressions are filled from the
    /// process environment and every value is checked. Without it, each
    /// expression is checked by syntax and position only: the loader replaces
    /// a value that holds one, as a whole, with the stand-in `stand_in_for`
    /// returns for the pointer of its member, so the members around it are
    /// still decoded, and a finding about that member's value is left out.
    /// Where `stand_in_for` returns [`DEFAULT_STAND_IN`], each different value
    /// takes a different stand-in, so two expressions in a set are not a
    /// repeat. A member that refuses its stand-in stops the decode: the check
    /// then reports a warning at that member, coded [`INCOMPLETE_CODE`], for
    /// the members it did not read.
    pub fn check_offline<T: DeserializeOwned>(
        &self,
        path: &Path,
        substitute: bool,
        stand_in_for: fn(&str) -> &'static str,
    ) -> RuntimeFileCheck<T> {
        let file = path.display().to_string();
        // One read under the loader's file rules serves the scan and the
        // decode, so nothing is opened before those rules have accepted it.
        let bytes = self.read_file(path);
        let tree = bytes.as_deref().ok().and_then(|bytes| scan(&file, bytes));
        let deferred = match (&tree, substitute) {
            (Some(root), false) => Deferred::collect(root, stand_in_for),
            _ => Deferred::default(),
        };
        let loaded = bytes.and_then(|bytes| {
            if substitute {
                self.parse_file::<T>(path, &bytes, &|name| std::env::var(name).ok())
            } else {
                self.parse_file_with_stand_ins::<T>(path, &bytes, &|pointer| {
                    deferred.stand_in(pointer).to_owned()
                })
            }
        });
        let (loaded, diagnostics, unavailable) = match loaded {
            Ok(loaded) => (Some(loaded), Vec::new(), false),
            Err(error) => (
                None,
                error
                    .diagnostics()
                    .iter()
                    .map(|diagnostic| match deferred.hides(diagnostic) {
                        true => incomplete(diagnostic),
                        false => diagnostic.clone(),
                    })
                    .collect(),
                error
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic.code == UNAVAILABLE_CODE),
            ),
        };
        RuntimeFileCheck {
            loaded,
            diagnostics,
            unavailable,
            file,
            tree,
            deferred,
        }
    }
}

/// The file's tree, for positions and expression sites. Bytes the reader
/// cannot scan yield none; the loader then reports why.
fn scan(file: &str, bytes: &[u8]) -> Option<Node> {
    Reader::new(file).scan(bytes).ok().flatten()
}

/// The warning that stands for `hidden`, a finding about the value of a
/// member that holds a deferred expression: the stand-in did not satisfy the
/// member, so the decode stopped there. It names the member and never a
/// value.
fn incomplete(hidden: &Diagnostic) -> Diagnostic {
    let mut diagnostic = Diagnostic::warning(
        INCOMPLETE_CODE,
        hidden.path.clone(),
        "the check does not fill the expression this member holds, and the value it puts in its \
         place is not one the member accepts; the check stopped here, and the members after it \
         were not checked",
        "Check the file again with --environment, where the variable the expression names is \
         set.",
    );
    diagnostic.artifact.clone_from(&hidden.artifact);
    diagnostic.source.clone_from(&hidden.source);
    diagnostic
}

/// The members that hold a `${NAME}` expression, each with the stand-in
/// value that fills it.
#[derive(Debug, Default)]
struct Deferred {
    pointers: Vec<String>,
    stand_ins: BTreeMap<String, String>,
}

/// The codes whose finding depends on a member's value rather than its
/// position or type.
const VALUE_CODES: &[&str] = &[
    "config.invalid-value",
    "config.invalid-length",
    "config.unknown-variant",
    "config.out-of-range",
];

impl Deferred {
    fn collect(root: &Node, stand_in_for: fn(&str) -> &'static str) -> Deferred {
        let mut deferred = Deferred::default();
        deferred.walk(root, &mut String::new(), stand_in_for, &mut BTreeMap::new());
        deferred
    }

    /// `defaults` numbers each different value met so far whose member names
    /// no stand-in of its own, in file order.
    fn walk<'n>(
        &mut self,
        node: &'n Node,
        pointer: &mut String,
        stand_in_for: fn(&str) -> &'static str,
        defaults: &mut BTreeMap<&'n str, usize>,
    ) {
        match &node.value {
            NodeValue::String(text) if contains_environment_expression(&text.text) => {
                let stand_in = match stand_in_for(pointer) {
                    DEFAULT_STAND_IN => default_stand_in(&text.text, defaults),
                    named => named.to_owned(),
                };
                self.stand_ins.insert(pointer.clone(), stand_in);
                self.pointers.push(pointer.clone());
            }
            NodeValue::Sequence(items) => {
                for (index, item) in items.iter().enumerate() {
                    let length = pointer.len();
                    pointer.push_str(&format!("/{index}"));
                    self.walk(item, pointer, stand_in_for, defaults);
                    pointer.truncate(length);
                }
            }
            NodeValue::Mapping(entries) => {
                for entry in entries {
                    let length = pointer.len();
                    pointer.push('/');
                    pointer.push_str(&escape_pointer_segment(&entry.key));
                    self.walk(&entry.value, pointer, stand_in_for, defaults);
                    pointer.truncate(length);
                }
            }
            _ => {}
        }
    }

    fn stand_in(&self, pointer: &str) -> &str {
        self.stand_ins
            .get(pointer)
            .map_or(DEFAULT_STAND_IN, String::as_str)
    }

    fn covers(&self, path: &str) -> bool {
        self.pointers.iter().any(|pointer| {
            path == pointer
                || path
                    .strip_prefix(pointer.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }

    fn lies_below(&self, path: &str) -> bool {
        self.pointers.iter().any(|pointer| {
            pointer
                .strip_prefix(path)
                .is_some_and(|rest| rest.starts_with('/'))
        })
    }

    fn hides(&self, diagnostic: &Diagnostic) -> bool {
        VALUE_CODES.contains(&diagnostic.code.as_str()) && self.covers(&diagnostic.path)
    }
}

/// The stand-in for `text`, the value of a member that names none of its
/// own: [`DEFAULT_STAND_IN`] for the first value in `defaults`, and that word
/// with a number for each different value after it. The same value written
/// twice takes the same stand-in, as it takes the same text in the runtime.
fn default_stand_in<'n>(text: &'n str, defaults: &mut BTreeMap<&'n str, usize>) -> String {
    let next = defaults.len() + 1;
    match *defaults.entry(text).or_insert(next) {
        1 => DEFAULT_STAND_IN.to_owned(),
        number => format!("{DEFAULT_STAND_IN}-{number}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeEnvelope;
    use serde::Deserialize;
    use std::fs;

    const LOADER: RuntimeConfigLoader = RuntimeConfigLoader::new(RuntimeEnvelope {
        api_version: "registry.registrystack.org/example-runtime/v1alpha1",
        kind: "ExampleRuntimeConfig",
    });

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    #[allow(dead_code)]
    struct Example {
        api_version: String,
        kind: String,
        bind: crate::ListenerBind,
        #[serde(default)]
        label: Option<registry_platform_yaml::LocalId>,
        #[serde(default)]
        origin: Option<registry_platform_yaml::Url>,
        #[serde(default)]
        names: registry_platform_yaml::UniqueList<registry_platform_yaml::LocalId>,
        count: registry_platform_yaml::BoundedU32<1, 10>,
    }

    fn stand_in_for(pointer: &str) -> &'static str {
        match pointer {
            "/bind" => "127.0.0.1:8080",
            _ => DEFAULT_STAND_IN,
        }
    }

    fn check(text: &str, substitute: bool) -> RuntimeFileCheck<Example> {
        let temporary = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = temporary.path().join("runtime.yaml");
        fs::write(&path, text).unwrap();
        LOADER.check_offline::<Example>(&path, substitute, stand_in_for)
    }

    const HEAD: &str = "apiVersion: registry.registrystack.org/example-runtime/v1alpha1\n\
                        kind: ExampleRuntimeConfig\n";

    #[test]
    fn cfg_check_1_an_expression_is_checked_by_position_without_the_environment() {
        let text = format!("{HEAD}bind: \"${{OFFLINE_CHECK_UNSET_BIND}}\"\ncount: 3\n");
        let deferred = check(&text, false);
        assert!(
            deferred.diagnostics.is_empty(),
            "{:?}",
            deferred.diagnostics
        );
        assert!(deferred.defers("/bind"));
        assert!(!deferred.defers("/count"));
        assert!(!deferred.defers(""));
        assert!(deferred.defers_within(""));
        assert!(deferred.defers_within("/bind"));
        assert!(!deferred.defers_within("/count"));
        assert!(!deferred.defers_within("/bin"));
        assert_eq!(
            deferred.loaded.unwrap().config.bind.socket_addr().port(),
            8080
        );

        let substituted = check(&text, true);
        assert_eq!(substituted.diagnostics[0].code, "config.substitution");
        assert_eq!(substituted.diagnostics[0].path, "/bind");
    }

    #[test]
    fn cfg_check_1_findings_away_from_an_expression_are_reported() {
        let text = format!("{HEAD}bind: \"${{OFFLINE_CHECK_UNSET_BIND}}\"\ncount: 11\n");
        let check = check(&text, false);
        assert_eq!(check.diagnostics.len(), 1);
        assert_eq!(check.diagnostics[0].code, "config.out-of-range");
        assert_eq!(check.diagnostics[0].path, "/count");
    }

    #[test]
    fn cfg_check_1_a_value_of_several_expressions_takes_the_stand_in_of_its_member() {
        let text = format!(
            "{HEAD}bind: \"${{OFFLINE_CHECK_UNSET_HOST}}:${{OFFLINE_CHECK_UNSET_PORT}}\"\ncount: 11\n"
        );
        let check = check(&text, false);
        assert!(check.defers("/bind"));
        // The member after the expressions is still read.
        let found: Vec<(&str, &str)> = check
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect();
        assert_eq!(found, [("config.out-of-range", "/count")]);
    }

    #[test]
    fn cfg_check_1_one_variable_in_two_members_takes_the_stand_in_of_each() {
        let text = format!(
            "{HEAD}bind: \"${{OFFLINE_CHECK_UNSET_SHARED}}\"\n\
             label: \"${{OFFLINE_CHECK_UNSET_SHARED}}\"\ncount: 3\n"
        );
        let check = check(&text, false);
        assert!(check.diagnostics.is_empty(), "{:?}", check.diagnostics);
        let config = check.loaded.expect("both members decode").config;
        assert_eq!(config.bind.socket_addr().port(), 8080);
        assert_eq!(config.label.as_deref(), Some(DEFAULT_STAND_IN));
    }

    #[test]
    fn cfg_check_1_two_expressions_in_a_set_are_not_a_repeat() {
        let text = format!(
            "{HEAD}bind: 127.0.0.1:8080\ncount: 3\n\
             names: [\"${{OFFLINE_CHECK_UNSET_A}}\", \"${{OFFLINE_CHECK_UNSET_B}}\"]\n"
        );
        let check = check(&text, false);
        assert!(check.diagnostics.is_empty(), "{:?}", check.diagnostics);
        let config = check.loaded.expect("the set decodes").config;
        assert_eq!(config.names.len(), 2);
        assert_ne!(config.names[0], config.names[1]);
    }

    #[test]
    fn cfg_check_1_one_expression_twice_in_a_set_is_a_repeat() {
        let text = format!(
            "{HEAD}bind: 127.0.0.1:8080\ncount: 3\n\
             names: [\"${{OFFLINE_CHECK_UNSET_A}}\", \"${{OFFLINE_CHECK_UNSET_A}}\"]\n"
        );
        let check = check(&text, false);
        assert_eq!(check.diagnostics.len(), 1, "{:?}", check.diagnostics);
        assert_eq!(check.diagnostics[0].code, "config.duplicate-item");
    }

    #[test]
    fn cfg_check_1_a_stand_in_the_member_refuses_leaves_the_check_incomplete() {
        // `origin` takes a URL and this product names no stand-in for it, so
        // the decode stops there and `count` is never read.
        let text = format!(
            "{HEAD}bind: 127.0.0.1:8080\norigin: \"${{OFFLINE_CHECK_UNSET_ORIGIN}}\"\ncount: 11\n"
        );
        // Substituting from the environment checks the value itself.
        let substituted = check(&text, true);
        assert_eq!(substituted.diagnostics[0].code, "config.substitution");

        let check = check(&text, false);
        assert!(check.loaded.is_none());
        assert!(!check.unavailable);
        assert_eq!(check.diagnostics.len(), 1, "{:?}", check.diagnostics);
        let diagnostic = &check.diagnostics[0];
        assert_eq!(
            diagnostic.severity,
            registry_platform_yaml::Severity::Warning
        );
        assert_eq!(diagnostic.code, INCOMPLETE_CODE);
        assert_eq!(diagnostic.path, "/origin");
        let source = diagnostic.source.as_ref().unwrap();
        assert_eq!((source.line, source.column), (Some(4), Some(9)));
        for text in [&diagnostic.message, &diagnostic.suggested_action] {
            assert!(!text.contains("OFFLINE_CHECK_UNSET_ORIGIN"), "{text}");
            assert!(!text.contains(DEFAULT_STAND_IN), "{text}");
        }
    }

    #[test]
    fn cfg_diag_1_a_product_finding_is_positioned_at_its_value() {
        let text = format!("{HEAD}bind: 127.0.0.1:8080\ncount: 3\n");
        let check = check(&text, false);
        let diagnostic = check.error_at(
            "ExampleRuntimeConfig",
            "example.runtime.public-bind",
            "/bind",
            "the address is public",
            "Bind a private address.",
        );
        let source = diagnostic.source.unwrap();
        assert_eq!((source.line, source.column), (Some(3), Some(7)));
        assert_eq!(diagnostic.artifact.as_deref(), Some("ExampleRuntimeConfig"));
    }

    #[test]
    fn cfg_check_1_an_unreadable_file_is_an_operational_failure() {
        let temporary = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let check = LOADER.check_offline::<Example>(
            &temporary.path().join("missing.yaml"),
            false,
            stand_in_for,
        );
        assert!(check.unavailable);
        assert!(check.loaded.is_none());
        assert_eq!(check.diagnostics.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn cfg_check_1_a_named_pipe_is_refused_without_being_opened() {
        use std::sync::mpsc;
        use std::time::Duration;

        let temporary = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = temporary.path().join("runtime.yaml");
        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(made.success());

        let (sender, receiver) = mpsc::channel();
        let checked = path.clone();
        std::thread::spawn(move || {
            let check = LOADER.check_offline::<Example>(&checked, false, stand_in_for);
            let _ = sender.send((check.unavailable, check.loaded.is_none(), check.diagnostics));
        });
        let Ok((unavailable, refused, diagnostics)) =
            receiver.recv_timeout(Duration::from_secs(10))
        else {
            // Opening the other end releases the checker a pipe is holding.
            let _ = fs::OpenOptions::new().write(true).open(&path);
            panic!("the check opened the named pipe and waited for a writer");
        };
        assert!(!unavailable);
        assert!(refused);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "platform.runtime-config.unsafe-file");
    }

    #[cfg(unix)]
    #[test]
    fn cfg_check_1_a_symbolic_link_is_refused_without_being_followed() {
        let temporary = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let real = temporary.path().join("real.yaml");
        fs::write(&real, format!("{HEAD}bind: 127.0.0.1:8080\ncount: 3\n")).unwrap();
        let link = temporary.path().join("runtime.yaml");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let check = LOADER.check_offline::<Example>(&link, false, stand_in_for);
        assert!(check.loaded.is_none());
        assert_eq!(check.diagnostics.len(), 1);
        assert_eq!(
            check.diagnostics[0].code,
            "platform.runtime-config.unsafe-file"
        );
        // Nothing of the link's target was read, so no member has a position.
        let positioned = check.error_at("ExampleRuntimeConfig", "example.code", "/bind", "m", "a");
        assert_eq!(positioned.source.unwrap().line, None);
    }
}
