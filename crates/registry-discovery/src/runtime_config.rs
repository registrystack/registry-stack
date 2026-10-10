// SPDX-License-Identifier: Apache-2.0
//! The Discovery runtime configuration: its types, the shared loader that
//! reads it, and the offline check `discoveryctl check --runtime-config` runs.

use std::path::Path;
use std::time::Duration;

use registry_platform_config::{
    ConfigBlockError, ConfigBlockErrorKind, ListenerBind, PackageConfig, RemovedKey,
    RuntimeConfigLoader, RuntimeEnvelope,
};
use registry_platform_yaml::{escape_pointer_segment, BoundedU64, Diagnostic, RetiredApiVersion};
use serde::Deserialize;

use crate::model::{
    MAXIMUM_HTTP_BODY_BYTES, MAXIMUM_RESULT_ALTERNATIVES, MAXIMUM_RESULT_RECORDS,
    MINIMUM_HTTP_RESPONSE_BYTES,
};

pub const RUNTIME_API_VERSION: &str = "id.registrystack.org/formats/discovery/runtime/v1alpha1";
pub const RUNTIME_KIND: &str = "DiscoveryRuntimeConfig";

/// The apiVersions an earlier Discovery runtime file carried, each refused
/// with the one that replaced it.
const RETIRED_RUNTIME_API_VERSIONS: &[RetiredApiVersion<'static>] = &[RetiredApiVersion {
    api_version: "registry.registrystack.org/discovery-runtime/v1alpha1",
    replacement: "Write apiVersion: id.registrystack.org/formats/discovery/runtime/v1alpha1.",
}];

const RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: RUNTIME_API_VERSION,
    kind: RUNTIME_KIND,
};

const REMOVED_RUNTIME_KEYS: &[RemovedKey] = &[
    RemovedKey {
        path: "schemaVersion",
        replacement: "declare apiVersion id.registrystack.org/formats/discovery/runtime/v1alpha1 \
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
    RemovedKey {
        path: "limits.requestTimeoutSeconds",
        replacement: "declare listener.requestTimeoutMilliseconds instead, with the value \
                      multiplied by 1000",
    },
    RemovedKey {
        path: "limits.shutdownTimeoutSeconds",
        replacement: "declare limits.shutdownGraceMilliseconds instead, with the value \
                      multiplied by 1000",
    },
];

const MAXIMUM_BODY_BYTES: u64 = MAXIMUM_HTTP_BODY_BYTES as u64;
const MINIMUM_RESPONSE_BYTES: u64 = MINIMUM_HTTP_RESPONSE_BYTES as u64;
const MAXIMUM_RECORDS: u64 = MAXIMUM_RESULT_RECORDS as u64;
const MAXIMUM_ALTERNATIVES: u64 = MAXIMUM_RESULT_ALTERNATIVES as u64;
const MINIMUM_TIMEOUT_MILLISECONDS: u64 = 1_000;
const MAXIMUM_TIMEOUT_MILLISECONDS: u64 = 300_000;

/// The address the service listens on and the time it gives one request.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeListener {
    pub bind: ListenerBind,
    /// Time allowed to handle one inbound request, in milliseconds.
    pub request_timeout_milliseconds:
        BoundedU64<MINIMUM_TIMEOUT_MILLISECONDS, MAXIMUM_TIMEOUT_MILLISECONDS>,
}

impl RuntimeListener {
    /// `requestTimeoutMilliseconds` as a duration.
    #[must_use]
    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_milliseconds.get())
    }
}

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
    /// Time allowed to drain in-flight requests on shutdown, in milliseconds.
    pub shutdown_grace_milliseconds:
        BoundedU64<MINIMUM_TIMEOUT_MILLISECONDS, MAXIMUM_TIMEOUT_MILLISECONDS>,
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

    /// `shutdownGraceMilliseconds` as a duration.
    #[must_use]
    pub fn shutdown_grace(&self) -> Duration {
        Duration::from_millis(self.shutdown_grace_milliseconds.get())
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
    pub listener: RuntimeListener,
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

/// The loader for the Discovery runtime file, with its removed keys and its
/// retired apiVersions.
#[must_use]
pub const fn runtime_loader() -> RuntimeConfigLoader {
    RuntimeConfigLoader::new(RUNTIME_ENVELOPE)
        .removed_keys(REMOVED_RUNTIME_KEYS)
        .retired_api_versions(RETIRED_RUNTIME_API_VERSIONS)
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
    read_runtime(path, substitute).1
}

/// Read the runtime file at `path` with the process environment, as the
/// service does at startup. A refusal is every finding, each positioned in
/// the file and naming its fix.
pub fn load_runtime_config(path: &Path) -> Result<RuntimeConfig, Vec<Diagnostic>> {
    match read_runtime(path, true) {
        (Some(config), _) => Ok(config),
        (None, check) => Err(check.diagnostics),
    }
}

/// The file read by the shared loader, then its package block checked. The
/// configuration is returned only when nothing was found.
fn read_runtime(path: &Path, substitute: bool) -> (Option<RuntimeConfig>, RuntimeCheck) {
    let check = runtime_loader().check_offline::<RuntimeConfig>(path, substitute, stand_in_for);
    let mut diagnostics = check.diagnostics.clone();
    if let Some(loaded) = &check.loaded {
        if let Err(error) = loaded.config.package.check() {
            let pointer = pointer_of(error.field());
            if !check.defers(&pointer) {
                let (code, action) = package_finding(&error);
                diagnostics.push(check.error_at(
                    RUNTIME_KIND,
                    code,
                    &pointer,
                    error.to_string(),
                    action,
                ));
            }
        }
    }
    let config = check
        .loaded
        .map(|loaded| loaded.config)
        .filter(|_| diagnostics.is_empty());
    (
        config,
        RuntimeCheck {
            diagnostics,
            unavailable: check.unavailable,
        },
    )
}

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
        _ => registry_platform_config::DEFAULT_STAND_IN,
    }
}

fn pointer_of(dotted: &str) -> String {
    dotted
        .split('.')
        .map(|segment| format!("/{}", escape_pointer_segment(segment)))
        .collect()
}

/// The code and fix for a shared package block refusal.
fn package_finding(error: &ConfigBlockError) -> (&'static str, &'static str) {
    match error.kind() {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const RUNTIME: &str = "\
apiVersion: id.registrystack.org/formats/discovery/runtime/v1alpha1
kind: DiscoveryRuntimeConfig
listener: { bind: 127.0.0.1:8080, requestTimeoutMilliseconds: 10000 }
package:
  root: /tmp/registry-discovery-package
limits:
  maximumRequestBytes: 65536
  maximumResponseBytes: 1048576
  maximumResultRecords: 100
  maximumResultAlternatives: 100
  shutdownGraceMilliseconds: 10000
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
    fn cfg_env_2_the_runtime_file_names_its_format_identifier() {
        assert_eq!(
            RUNTIME_API_VERSION,
            "id.registrystack.org/formats/discovery/runtime/v1alpha1"
        );
        assert!(RUNTIME.contains(RUNTIME_API_VERSION));
    }

    #[test]
    fn cfg_change_2_the_retired_api_version_names_its_replacement() {
        let check = check(
            &RUNTIME.replace(
                RUNTIME_API_VERSION,
                "registry.registrystack.org/discovery-runtime/v1alpha1",
            ),
            false,
        );
        assert_eq!(
            codes(&check),
            [("config.retired-api-version", "/apiVersion")]
        );
        let action = check.diagnostics[0].suggested_action.as_str();
        assert!(action.contains(RUNTIME_API_VERSION), "{action}");
    }

    #[test]
    fn cfg_name_5_the_timeouts_are_read_in_milliseconds() {
        let temporary = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let path = temporary.path().join("runtime.yaml");
        fs::write(&path, RUNTIME).unwrap();
        let runtime = load_runtime_config(&path).unwrap();
        assert_eq!(runtime.listener.request_timeout(), Duration::from_secs(10));
        assert_eq!(runtime.limits.shutdown_grace(), Duration::from_secs(10));

        // A value written in seconds under the millisecond name is below the
        // floor, so a file that renamed the key and kept the number is told.
        let check = check(
            &RUNTIME.replace(
                "requestTimeoutMilliseconds: 10000",
                "requestTimeoutMilliseconds: 10",
            ),
            false,
        );
        assert_eq!(
            codes(&check),
            [(
                "config.out-of-range",
                "/listener/requestTimeoutMilliseconds"
            )]
        );
        assert!(
            check.diagnostics[0].message.contains("1000 to 300000"),
            "{}",
            check.diagnostics[0].message
        );
    }

    #[test]
    fn cfg_change_2_the_second_valued_timeouts_name_their_replacements() {
        // The request timeout moved to the listener it bounds; the shutdown
        // grace stays among the limits under its shared name.
        for (old, new) in [
            (
                "requestTimeoutSeconds",
                "listener.requestTimeoutMilliseconds",
            ),
            ("shutdownTimeoutSeconds", "limits.shutdownGraceMilliseconds"),
        ] {
            let check = check(
                &RUNTIME.replace(
                    "  shutdownGraceMilliseconds: 10000",
                    &format!("  shutdownGraceMilliseconds: 10000\n  {old}: 10"),
                ),
                false,
            );
            assert_eq!(
                codes(&check),
                [("config.removed-key", format!("/limits/{old}").as_str())]
            );
            let action = check.diagnostics[0].suggested_action.as_str();
            assert!(action.contains(new), "{action}");
        }
    }

    #[test]
    fn cfg_qty_4_a_limit_outside_its_bounds_is_refused_at_the_member() {
        let check = check(
            &RUNTIME
                .replace("maximumRequestBytes: 65536", "maximumRequestBytes: 0")
                .replace(
                    "shutdownGraceMilliseconds: 10000",
                    "shutdownGraceMilliseconds: 300001",
                ),
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
}
