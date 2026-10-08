// SPDX-License-Identifier: Apache-2.0
//! The offline check of a runtime file (CFG-CHECK-1): the file read as the
//! runtime reads it, with no secret material and, unless asked, no process
//! environment.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::Path;

use registry_platform_yaml::{
    escape_pointer_segment, Diagnostic, Node, NodeValue, Reader, Source, MAXIMUM_DOCUMENT_BYTES,
};
use serde::de::DeserializeOwned;

use crate::{
    contains_environment_expression, LoadedRuntimeConfig, RuntimeConfigErrorKind,
    RuntimeConfigLoader,
};

/// The stand-in for a deferred expression whose member names no other.
pub const DEFAULT_STAND_IN: &str = "deferred";

/// What an offline check of one runtime file found.
#[derive(Debug)]
pub struct RuntimeFileCheck<T> {
    /// The decoded configuration, when the loader accepted the file. A
    /// member that holds a deferred expression carries its stand-in.
    pub loaded: Option<LoadedRuntimeConfig<T>>,
    /// Every loader finding, each naming the file as the path was given,
    /// less those that depend on the value of a deferred expression.
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
    /// expression is checked by syntax and position only: the loader fills
    /// it with the stand-in `stand_in_for` returns for the pointer of the
    /// member that holds it, so the members around it are still decoded, and
    /// a finding about that member's value is left out.
    pub fn check_offline<T: DeserializeOwned>(
        &self,
        path: &Path,
        substitute: bool,
        stand_in_for: fn(&str) -> &'static str,
    ) -> RuntimeFileCheck<T> {
        let file = path.display().to_string();
        let tree = scan(path);
        let deferred = match (&tree, substitute) {
            (Some(root), false) => Deferred::collect(root, stand_in_for),
            _ => Deferred::default(),
        };
        let loaded = if substitute {
            self.load::<T>(path)
        } else {
            self.load_with::<T>(path, |name| Some(deferred.stand_in(name).to_owned()))
        };
        let (loaded, diagnostics, unavailable) = match loaded {
            Ok(loaded) => (Some(loaded), Vec::new(), false),
            Err(error) => (
                None,
                error
                    .diagnostics()
                    .iter()
                    .filter(|diagnostic| !deferred.hides(diagnostic))
                    .cloned()
                    .collect(),
                error.kind() == RuntimeConfigErrorKind::Unavailable,
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

/// The file's tree, for positions and expression sites. A file the reader
/// cannot scan yields none; the loader then reports why.
fn scan(path: &Path) -> Option<Node> {
    let file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAXIMUM_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    Reader::new(path.display().to_string())
        .scan(&bytes)
        .ok()
        .flatten()
}

/// The members that hold a `${NAME}` expression, and a stand-in value for
/// each name that satisfies the member it fills.
#[derive(Debug, Default)]
struct Deferred {
    pointers: Vec<String>,
    stand_ins: BTreeMap<String, &'static str>,
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
        deferred.walk(root, &mut String::new(), stand_in_for);
        deferred
    }

    fn walk(&mut self, node: &Node, pointer: &mut String, stand_in_for: fn(&str) -> &'static str) {
        match &node.value {
            NodeValue::String(text) if contains_environment_expression(&text.text) => {
                let stand_in = stand_in_for(pointer);
                for name in expression_names(&text.text) {
                    self.stand_ins.entry(name.to_owned()).or_insert(stand_in);
                }
                self.pointers.push(pointer.clone());
            }
            NodeValue::Sequence(items) => {
                for (index, item) in items.iter().enumerate() {
                    let length = pointer.len();
                    pointer.push_str(&format!("/{index}"));
                    self.walk(item, pointer, stand_in_for);
                    pointer.truncate(length);
                }
            }
            NodeValue::Mapping(entries) => {
                for entry in entries {
                    let length = pointer.len();
                    pointer.push('/');
                    pointer.push_str(&escape_pointer_segment(&entry.key));
                    self.walk(&entry.value, pointer, stand_in_for);
                    pointer.truncate(length);
                }
            }
            _ => {}
        }
    }

    fn stand_in(&self, name: &str) -> &'static str {
        self.stand_ins
            .get(name)
            .copied()
            .unwrap_or(DEFAULT_STAND_IN)
    }

    fn covers(&self, path: &str) -> bool {
        self.pointers.iter().any(|pointer| {
            path == pointer
                || path
                    .strip_prefix(pointer.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }

    fn hides(&self, diagnostic: &Diagnostic) -> bool {
        VALUE_CODES.contains(&diagnostic.code.as_str()) && self.covers(&diagnostic.path)
    }
}

/// The variable names of the `${NAME}`, `${NAME:-...}` and `${NAME:?...}`
/// expressions in `text`.
fn expression_names(text: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let end = after
            .find(|character: char| character != '_' && !character.is_ascii_alphanumeric())
            .unwrap_or(after.len());
        let (name, tail) = after.split_at(end);
        if !name.is_empty()
            && (tail.starts_with('}') || tail.starts_with(":-") || tail.starts_with(":?"))
        {
            names.push(name);
        }
        rest = after;
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeEnvelope;
    use serde::Deserialize;

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

    #[test]
    fn expression_names_are_read_from_every_expression_form() {
        assert_eq!(
            expression_names("${A}:${B:-x}/${C:?set C}${ not}${}"),
            ["A", "B", "C"]
        );
    }
}
