// SPDX-License-Identifier: Apache-2.0
//! The Discovery runtime configuration: its types, the shared loader that
//! reads it, and the offline check `discoveryctl check --runtime-config` runs.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::Path;

use registry_platform_config::{
    contains_environment_expression, ConfigBlockError, ConfigBlockErrorKind, ListenerConfig,
    PackageConfig, RemovedKey, RuntimeConfigErrorKind, RuntimeConfigLoader, RuntimeEnvelope,
};
use registry_platform_yaml::{
    escape_pointer_segment, BoundedU64, Diagnostic, Node, NodeValue, Reader, Source,
    MAXIMUM_DOCUMENT_BYTES,
};
use serde::Deserialize;

use crate::model::{
    MAXIMUM_HTTP_BODY_BYTES, MAXIMUM_RESULT_ALTERNATIVES, MAXIMUM_RESULT_RECORDS,
    MINIMUM_HTTP_RESPONSE_BYTES,
};

pub const RUNTIME_API_VERSION: &str = "registry.registrystack.org/discovery-runtime/v1alpha1";
pub const RUNTIME_KIND: &str = "DiscoveryRuntimeConfig";

const RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: RUNTIME_API_VERSION,
    kind: RUNTIME_KIND,
};

const REMOVED_RUNTIME_KEYS: &[RemovedKey] = &[
    RemovedKey {
        path: "schemaVersion",
        replacement: "declare apiVersion registry.registrystack.org/discovery-runtime/v1alpha1 \
                      and kind DiscoveryRuntimeConfig instead",
    },
    RemovedKey {
        path: "listener.address",
        replacement: "declare listener.bind instead",
    },
    RemovedKey {
        path: "indexPath",
        replacement: "declare package.root instead and build it with `discoveryctl package`",
    },
];

const MAXIMUM_BODY_BYTES: u64 = MAXIMUM_HTTP_BODY_BYTES as u64;
const MINIMUM_RESPONSE_BYTES: u64 = MINIMUM_HTTP_RESPONSE_BYTES as u64;
const MAXIMUM_RECORDS: u64 = MAXIMUM_RESULT_RECORDS as u64;
const MAXIMUM_ALTERNATIVES: u64 = MAXIMUM_RESULT_ALTERNATIVES as u64;
const MAXIMUM_TIMEOUT_SECONDS: u64 = 300;

/// The bounds the service applies to every request and response.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(inline))]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeLimits {
    /// Largest request body, in bytes, the service reads.
    pub maximum_request_bytes: BoundedU64<1, MAXIMUM_BODY_BYTES>,
    /// Largest response body, in bytes, the service writes.
    pub maximum_response_bytes: BoundedU64<MINIMUM_RESPONSE_BYTES, MAXIMUM_BODY_BYTES>,
    /// Most service records one response returns.
    pub maximum_result_records: BoundedU64<1, MAXIMUM_RECORDS>,
    /// Most evidence-type alternatives one response returns.
    pub maximum_result_alternatives: BoundedU64<1, MAXIMUM_ALTERNATIVES>,
    /// Time allowed to handle one inbound request, in seconds.
    pub request_timeout_seconds: BoundedU64<1, MAXIMUM_TIMEOUT_SECONDS>,
    /// Time allowed to drain in-flight requests on shutdown, in seconds.
    pub shutdown_timeout_seconds: BoundedU64<1, MAXIMUM_TIMEOUT_SECONDS>,
}

impl RuntimeLimits {
    /// `maximumRequestBytes` as a length; the bound keeps it within `usize`.
    #[must_use]
    pub fn request_bytes(&self) -> usize {
        to_length(self.maximum_request_bytes.get())
    }

    /// `maximumResponseBytes` as a length.
    #[must_use]
    pub fn response_bytes(&self) -> usize {
        to_length(self.maximum_response_bytes.get())
    }

    /// `maximumResultRecords` as a count.
    #[must_use]
    pub fn result_records(&self) -> usize {
        to_length(self.maximum_result_records.get())
    }

    /// `maximumResultAlternatives` as a count.
    #[must_use]
    pub fn result_alternatives(&self) -> usize {
        to_length(self.maximum_result_alternatives.get())
    }
}

/// Every bound above is at most 16 MiB, which fits `usize` on every target
/// the workspace builds for.
fn to_length(value: u64) -> usize {
    usize::try_from(value).expect("a Discovery runtime bound fits usize")
}

/// The operator runtime configuration document.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    pub listener: ListenerConfig,
    /// The package directory `discoveryctl package` built.
    pub package: PackageConfig,
    pub limits: RuntimeLimits,
    /// The least severe event the service logs.
    pub log_level: LogLevel,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
}

/// The loader for the Discovery runtime file, with its removed keys.
#[must_use]
pub const fn runtime_loader() -> RuntimeConfigLoader {
    RuntimeConfigLoader::new(RUNTIME_ENVELOPE).removed_keys(REMOVED_RUNTIME_KEYS)
}

/// What an offline check of one runtime file found.
#[derive(Debug)]
pub struct RuntimeCheck {
    /// Every finding, each naming the file as `path` was given.
    pub diagnostics: Vec<Diagnostic>,
    /// The file could not be read at all, as opposed to read and refused.
    pub unavailable: bool,
}

/// Check the runtime file at the absolute `path` as `discovery serve` reads
/// it, with no package, network, or secret material (CFG-CHECK-1).
///
/// With `substitute` set, `${NAME}` expressions are filled from the process
/// environment and every value is checked. Without it, each expression is
/// checked by syntax and position only: the value checks of a member that
/// holds one are skipped, because they need the substituted text.
#[must_use]
pub fn check_runtime(path: &Path, substitute: bool) -> RuntimeCheck {
    let tree = scan(path);
    let deferred = match (&tree, substitute) {
        (Some(root), false) => Deferred::collect(root),
        _ => Deferred::default(),
    };
    let loaded = if substitute {
        runtime_loader().load::<RuntimeConfig>(path)
    } else {
        runtime_loader()
            .load_with::<RuntimeConfig>(path, |name| Some(deferred.stand_in(name).to_owned()))
    };
    match loaded {
        Ok(loaded) => {
            let mut diagnostics = Vec::new();
            if let Err(error) = loaded.config.package.check() {
                let pointer = pointer_of(error.field());
                if !deferred.covers(&pointer) {
                    diagnostics.push(package_diagnostic(path, tree.as_ref(), &pointer, &error));
                }
            }
            RuntimeCheck {
                diagnostics,
                unavailable: false,
            }
        }
        Err(error) => RuntimeCheck {
            diagnostics: error
                .diagnostics()
                .iter()
                .filter(|diagnostic| !deferred.hides(diagnostic))
                .cloned()
                .collect(),
            unavailable: error.kind() == RuntimeConfigErrorKind::Unavailable,
        },
    }
}

/// Read the runtime file at `path` with the process environment, as the
/// service does at startup. A refusal is every finding, each positioned in
/// the file and naming its fix.
pub fn load_runtime_config(path: &Path) -> Result<RuntimeConfig, Vec<Diagnostic>> {
    let config = runtime_loader()
        .load::<RuntimeConfig>(path)
        .map_err(|error| error.diagnostics().to_vec())?
        .config;
    if let Err(error) = config.package.check() {
        let pointer = pointer_of(error.field());
        return Err(vec![package_diagnostic(
            path,
            scan(path).as_ref(),
            &pointer,
            &error,
        )]);
    }
    Ok(config)
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
/// each name that satisfies the member it fills, so the members around it
/// are still decoded and checked.
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
    fn collect(root: &Node) -> Deferred {
        let mut deferred = Deferred::default();
        deferred.walk(root, &mut String::new());
        deferred
    }

    fn walk(&mut self, node: &Node, pointer: &mut String) {
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
                    self.walk(item, pointer);
                    pointer.truncate(length);
                }
            }
            NodeValue::Mapping(entries) => {
                for entry in entries {
                    let length = pointer.len();
                    pointer.push('/');
                    pointer.push_str(&escape_pointer_segment(&entry.key));
                    self.walk(&entry.value, pointer);
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

const DEFAULT_STAND_IN: &str = "deferred";

/// A value that satisfies the member at `pointer`, so a deferred expression
/// never decides whether its neighbours decode.
fn stand_in_for(pointer: &str) -> &'static str {
    match pointer {
        "/listener/bind" => "127.0.0.1:8080",
        "/package/root" => "/",
        "/package/expectedDigest" => {
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
        "/logLevel" => "info",
        _ => DEFAULT_STAND_IN,
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

fn pointer_of(dotted: &str) -> String {
    dotted
        .split('.')
        .map(|segment| format!("/{}", escape_pointer_segment(segment)))
        .collect()
}

/// A shared package block refusal as a positioned Discovery diagnostic.
fn package_diagnostic(
    path: &Path,
    tree: Option<&Node>,
    pointer: &str,
    error: &ConfigBlockError,
) -> Diagnostic {
    let (code, action) = match error.kind() {
        ConfigBlockErrorKind::RelativePath => (
            "discovery.runtime.relative-package-root",
            "Write package.root as an absolute path with no `.` or `..` segment.",
        ),
        ConfigBlockErrorKind::InvalidDigest => (
            "discovery.runtime.invalid-package-digest",
            "Write package.expectedDigest as the `sha256:` digest `discoveryctl package` printed, \
             or remove it.",
        ),
        _ => (
            "discovery.runtime.invalid-package",
            "Correct the package block as the message describes.",
        ),
    };
    let mut diagnostic = Diagnostic::error(code, pointer, error.to_string(), action);
    diagnostic.artifact = Some(RUNTIME_KIND.to_owned());
    let position = tree
        .and_then(|root| root.pointer(pointer))
        .map(|node| node.span.start);
    diagnostic.source = Some(Source {
        file: path.display().to_string(),
        line: position.map(|position| position.line),
        column: position.map(|position| position.column),
    });
    diagnostic
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNTIME: &str = "\
apiVersion: registry.registrystack.org/discovery-runtime/v1alpha1
kind: DiscoveryRuntimeConfig
listener: { bind: 127.0.0.1:8080 }
package:
  root: /tmp/registry-discovery-package
limits:
  maximumRequestBytes: 65536
  maximumResponseBytes: 1048576
  maximumResultRecords: 100
  maximumResultAlternatives: 100
  requestTimeoutSeconds: 10
  shutdownTimeoutSeconds: 10
logLevel: info
";

    fn check(text: &str, substitute: bool) -> RuntimeCheck {
        let temporary = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = temporary.path().join("runtime.yaml");
        fs::write(&path, text).unwrap();
        check_runtime(&path, substitute)
    }

    fn codes(check: &RuntimeCheck) -> Vec<(&str, &str)> {
        check
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect()
    }

    #[test]
    fn cfg_check_1_a_valid_runtime_file_checks_clean() {
        let check = check(RUNTIME, false);
        assert!(check.diagnostics.is_empty(), "{:?}", check.diagnostics);
        assert!(!check.unavailable);
    }

    #[test]
    fn cfg_qty_4_a_limit_outside_its_bounds_is_refused_at_the_member() {
        let check = check(
            &RUNTIME
                .replace("maximumRequestBytes: 65536", "maximumRequestBytes: 0")
                .replace("requestTimeoutSeconds: 10", "requestTimeoutSeconds: 301"),
            false,
        );
        // Decoding stops at the first value it refuses.
        assert_eq!(
            codes(&check),
            [("config.out-of-range", "/limits/maximumRequestBytes")]
        );
        let first = &check.diagnostics[0];
        assert_eq!(first.source.as_ref().unwrap().line, Some(7));
        assert!(first.message.contains("1 to 16777216"), "{}", first.message);
    }

    #[test]
    fn cfg_check_1_an_expression_is_checked_by_position_without_the_environment() {
        let text = RUNTIME
            .replace("127.0.0.1:8080", "\"${DISCOVERY_CHECK_UNSET_BIND}\"")
            .replace(
                "/tmp/registry-discovery-package",
                "${DISCOVERY_CHECK_UNSET_ROOT}",
            );
        assert!(check(&text, false).diagnostics.is_empty());

        // Substituting from the environment checks the values, and an unset
        // variable is reported where it is written.
        let substituted = check(&text, true);
        assert_eq!(
            codes(&substituted).first(),
            Some(&("config.substitution", "/listener/bind"))
        );

        // An expression in an integer position is a position finding, not a
        // value finding, so it is reported either way.
        let text = RUNTIME.replace("65536", "\"${DISCOVERY_CHECK_UNSET_BYTES}\"");
        assert_eq!(
            codes(&check(&text, false)),
            [("config.expected-integer", "/limits/maximumRequestBytes")]
        );
    }

    #[test]
    fn cfg_diag_1_a_relative_package_root_is_reported_at_its_value() {
        let check = check(
            &RUNTIME.replace("/tmp/registry-discovery-package", "package"),
            false,
        );
        assert_eq!(
            codes(&check),
            [("discovery.runtime.relative-package-root", "/package/root")]
        );
        let source = check.diagnostics[0].source.as_ref().unwrap();
        assert_eq!((source.line, source.column), (Some(5), Some(9)));
    }

    #[test]
    fn cfg_check_1_an_unreadable_file_is_an_operational_failure() {
        let temporary = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let check = check_runtime(&temporary.path().join("missing.yaml"), false);
        assert!(check.unavailable);
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
