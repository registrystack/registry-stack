//! The serve runtime: one strict YAML file with everything a deployment
//! owns: listener, verified bundle package, secret providers, caller key,
//! limits, audit. Nothing here can override governed (bundle) behavior.
//!
//! The file is read through the shared Registry Stack runtime configuration
//! loader, so its envelope, size bound, path rules, `${VAR}` substitution,
//! and secret provider declarations match every other runtime.

use std::path::{Path, PathBuf};
use std::time::Duration;

use registry_platform_audit::{
    AuditDestination, AuditDestinationError, AuditDestinationKind, MAX_AUDIT_RETAIN_DAYS,
    MIN_AUDIT_ROTATE_BYTES,
};
use registry_platform_config::{
    ConfigBlockError, ConfigBlockErrorKind, ListenerBind, LoadedRuntimeConfig, PackageConfig,
    RemovedKey, RuntimeConfigLoader, RuntimeEnvelope, SecretProvidersConfig,
};
use registry_platform_yaml::{
    escape_pointer_segment, BoundedU32, BoundedU64, Diagnostic, RetiredApiVersion,
};
use serde::Deserialize;

use crate::problem::{ProblemKind, RenderProblem};

pub const RUNTIME_API_VERSION: &str = "id.registrystack.org/formats/render/runtime/v1alpha1";
pub const RUNTIME_KIND: &str = "RenderRuntimeConfig";

const RENDER_RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: RUNTIME_API_VERSION,
    kind: RUNTIME_KIND,
};

/// The apiVersion a runtime file carried before its members took their
/// shared names, refused with the renames it needs.
const RETIRED_RUNTIME_API_VERSIONS: &[RetiredApiVersion<'static>] = &[RetiredApiVersion {
    api_version: "registry.registrystack.org/render-runtime/v1alpha1",
    replacement: "Write apiVersion id.registrystack.org/formats/render/runtime/v1alpha1, then \
                  rename listener.shutdownGraceSeconds to listener.shutdownGraceMilliseconds \
                  (the value times 1000), limits.maxOutputBytes to limits.maximumOutputBytes, \
                  limits.maxRequestBodyBytes to limits.maximumRequestBytes, \
                  limits.maxConcurrency to limits.maximumConcurrentRenders, and \
                  audit.retainDays to audit.retentionDays.",
}];

/// Keys an earlier runtime file carried, each refused with its replacement.
const RENDER_REMOVED_KEYS: &[RemovedKey] = &[
    RemovedKey {
        path: "server",
        replacement: "declare listener.bind and listener.shutdownGraceMilliseconds instead",
    },
    RemovedKey {
        path: "bundle",
        replacement: "declare package.root as the absolute path of the package directory",
    },
    RemovedKey {
        path: "listener.shutdownGraceSeconds",
        replacement: "declare listener.shutdownGraceMilliseconds instead, the value times 1000",
    },
    RemovedKey {
        path: "limits.maxOutputBytes",
        replacement: "declare limits.maximumOutputBytes instead",
    },
    RemovedKey {
        path: "limits.maxRequestBodyBytes",
        replacement: "declare limits.maximumRequestBytes instead",
    },
    RemovedKey {
        path: "limits.maxConcurrency",
        replacement: "declare limits.maximumConcurrentRenders instead",
    },
    RemovedKey {
        path: "audit.directory",
        replacement: "declare audit.path as the absolute path of the active audit file instead",
    },
    RemovedKey {
        path: "audit.integrityKeyRef",
        replacement: "remove it; audit entries are not hash-chained, so no integrity key is read",
    },
    RemovedKey {
        path: "audit.maxSegmentBytes",
        replacement: "declare audit.rotateBytes instead",
    },
    RemovedKey {
        path: "audit.retainDays",
        replacement: "declare audit.retentionDays instead",
    },
];

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RenderRuntime {
    pub api_version: String,
    pub kind: String,
    pub listener: ListenerRuntime,
    /// The verified bundle package Render serves.
    pub package: PackageConfig,
    pub secret_providers: SecretProvidersConfig,
    pub auth: AuthRuntime,
    #[serde(default)]
    pub limits: LimitsRuntime,
    pub audit: AuditRuntime,
}

/// The shortest grace a runtime may declare: zero would drop the renders
/// in flight the moment SIGTERM arrives.
pub const MINIMUM_SHUTDOWN_GRACE_MILLISECONDS: u64 = 1_000;

/// The longest grace a runtime may declare. Shutdown waits the grace for
/// renders in flight and then the same again for connections, so the bound
/// keeps that sum representable as well as operationally sane.
pub const MAXIMUM_SHUTDOWN_GRACE_MILLISECONDS: u64 = 3_600_000;

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListenerRuntime {
    /// Loopback, private, or link-local address to listen on. A public or
    /// all-interfaces bind is refused when the file is read. TLS is the
    /// proxy's job, not Render's.
    pub bind: ListenerBind,
    /// Time allowed for renders in flight to finish at shutdown, in
    /// milliseconds. Open connections get the same again.
    #[serde(default = "default_shutdown_grace")]
    pub shutdown_grace_milliseconds:
        BoundedU64<MINIMUM_SHUTDOWN_GRACE_MILLISECONDS, MAXIMUM_SHUTDOWN_GRACE_MILLISECONDS>,
}

impl ListenerRuntime {
    /// `shutdownGraceMilliseconds` as a duration.
    #[must_use]
    pub fn shutdown_grace(&self) -> Duration {
        Duration::from_millis(self.shutdown_grace_milliseconds.get())
    }
}

/// Whether Render may listen on `addr`: loopback, private, and link-local
/// addresses only.
fn bind_allowed(addr: std::net::SocketAddr) -> bool {
    match addr {
        std::net::SocketAddr::V4(a) => {
            let ip = a.ip();
            ip.is_loopback() || ip.is_private() || ip.is_link_local()
        }
        std::net::SocketAddr::V6(a) => {
            let ip = a.ip();
            ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
        }
    }
}

/// Render never listens on a public address: TLS termination and network
/// position belong to the deployment's proxy. Loopback, private, and
/// link-local addresses pass; unspecified (all interfaces) and public
/// addresses are refused with a named startup problem, an explicit refusal
/// instead of an accidental exposure.
pub fn validate_bind(addr: std::net::SocketAddr) -> Result<(), RenderProblem> {
    if bind_allowed(addr) {
        Ok(())
    } else {
        Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!(
                "listener.bind {addr} is not a loopback or private address; Render never \
                 listens publicly or on all interfaces; terminate TLS and position the \
                 service on a proxy, and bind its private address here"
            ),
        ))
    }
}

fn default_shutdown_grace(
) -> BoundedU64<MINIMUM_SHUTDOWN_GRACE_MILLISECONDS, MAXIMUM_SHUTDOWN_GRACE_MILLISECONDS> {
    BoundedU64::new(30_000).expect("the default grace is within its bounds")
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthRuntime {
    /// Secret reference to the caller API key, under a declared provider.
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_config::SecretReference")
    )]
    pub api_key_ref: String,
}

/// The longest render a runtime may allow.
pub const MAXIMUM_RENDER_TIMEOUT_SECONDS: u64 = 3_600;
/// The produced PDF never exceeds the renderer's own ceiling.
const MAXIMUM_OUTPUT_BYTES: u64 = crate::render::DEFAULT_MAX_OUTPUT_BYTES as u64;
/// The request body ceiling no runtime may raise past: 64 MiB.
const MAXIMUM_REQUEST_BYTES: u64 = 64 * 1024 * 1024;
const MAXIMUM_CONCURRENT_RENDERS: u64 = 64;

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LimitsRuntime {
    /// Wall-clock budget per render, in seconds; the worker is killed at
    /// this bound.
    #[serde(default = "default_render_timeout")]
    pub render_timeout_seconds: BoundedU64<1, MAXIMUM_RENDER_TIMEOUT_SECONDS>,
    /// Largest PDF a render may produce, in bytes.
    #[serde(default = "default_maximum_output_bytes")]
    pub maximum_output_bytes: BoundedU64<1, MAXIMUM_OUTPUT_BYTES>,
    /// Largest request body (data and base64 assets), in bytes. The httpsec
    /// default is 1 MiB; renders with photos need a conscious, bounded raise.
    #[serde(default = "default_maximum_request_bytes")]
    pub maximum_request_bytes: BoundedU64<1, MAXIMUM_REQUEST_BYTES>,
    /// Most renders in flight at once. Default: the CPU count, at most 8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU64<1, MAXIMUM_CONCURRENT_RENDERS>")
    )]
    pub maximum_concurrent_renders: Option<BoundedU64<1, MAXIMUM_CONCURRENT_RENDERS>>,
}

impl Default for LimitsRuntime {
    fn default() -> Self {
        Self {
            render_timeout_seconds: default_render_timeout(),
            maximum_output_bytes: default_maximum_output_bytes(),
            maximum_request_bytes: default_maximum_request_bytes(),
            maximum_concurrent_renders: None,
        }
    }
}

impl LimitsRuntime {
    /// `renderTimeoutSeconds` as a duration.
    #[must_use]
    pub fn render_timeout(&self) -> Duration {
        Duration::from_secs(self.render_timeout_seconds.get())
    }

    /// `maximumOutputBytes` as a length.
    #[must_use]
    pub fn output_bytes(&self) -> usize {
        to_length(self.maximum_output_bytes.get())
    }

    /// `maximumRequestBytes` as a length.
    #[must_use]
    pub fn request_bytes(&self) -> usize {
        to_length(self.maximum_request_bytes.get())
    }

    /// `maximumConcurrentRenders`, or the CPU count capped at 8 when the
    /// file leaves it out.
    #[must_use]
    pub fn concurrent_renders(&self) -> usize {
        self.maximum_concurrent_renders
            .map_or_else(default_concurrent_renders, |renders| {
                to_length(renders.get())
            })
    }
}

/// Every limit above is at most 64 MiB, which fits `usize` on every target
/// the workspace builds for.
fn to_length(value: u64) -> usize {
    usize::try_from(value).expect("a Render runtime limit fits usize")
}

pub fn default_render_timeout_seconds() -> u64 {
    20
}

fn default_render_timeout() -> BoundedU64<1, MAXIMUM_RENDER_TIMEOUT_SECONDS> {
    BoundedU64::new(default_render_timeout_seconds())
        .expect("the default render timeout is within its bounds")
}

fn default_maximum_output_bytes() -> BoundedU64<1, MAXIMUM_OUTPUT_BYTES> {
    BoundedU64::new(MAXIMUM_OUTPUT_BYTES).expect("the output ceiling is within its bounds")
}

fn default_maximum_request_bytes() -> BoundedU64<1, MAXIMUM_REQUEST_BYTES> {
    BoundedU64::new(8 * 1024 * 1024).expect("the default request ceiling is within its bounds")
}

fn default_concurrent_renders() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().min(8))
        .unwrap_or(2)
}

/// The largest `audit.rotateBytes` the shared audit writer accepts.
const MAXIMUM_AUDIT_ROTATE_BYTES: u64 = u32::MAX as u64;

/// The audit block every Registry Stack product shares: a `file` (the
/// default) or `stdout` destination, with rotation and retention for a file.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditRuntime {
    /// Where audit lines go: `file` or `stdout`.
    #[serde(default)]
    pub destination: AuditDestinationKind,
    /// The absolute path of the active audit file, for a `file` destination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "PathBuf"))]
    pub path: Option<PathBuf>,
    /// Size at which the active file rotates, in bytes, for a `file`
    /// destination. Default: 100 MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU64<MIN_AUDIT_ROTATE_BYTES, MAXIMUM_AUDIT_ROTATE_BYTES>")
    )]
    pub rotate_bytes: Option<BoundedU64<MIN_AUDIT_ROTATE_BYTES, MAXIMUM_AUDIT_ROTATE_BYTES>>,
    /// Days a rotated file is kept, for a `file` destination. Default: 90.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU32<1, MAX_AUDIT_RETAIN_DAYS>")
    )]
    pub retention_days: Option<BoundedU32<1, MAX_AUDIT_RETAIN_DAYS>>,
}

impl AuditRuntime {
    /// The destination the shared audit writer builds from this block.
    fn settings(&self) -> Result<AuditDestination, AuditDestinationError> {
        AuditDestination::from_settings(
            self.destination,
            self.path.clone(),
            self.rotate_bytes.map(BoundedU64::get),
            self.retention_days.map(BoundedU32::get),
        )
    }

    /// The validated destination the audit writer opens.
    pub fn destination(&self) -> Result<AuditDestination, RenderProblem> {
        self.settings().map_err(|error| {
            RenderProblem::new(ProblemKind::RuntimeInvalid, audit_finding(&error).message)
        })
    }
}

/// The loader for the Render runtime file, with its removed keys and its
/// retired apiVersion.
#[must_use]
pub const fn runtime_loader() -> RuntimeConfigLoader {
    RuntimeConfigLoader::new(RENDER_RUNTIME_ENVELOPE)
        .removed_keys(RENDER_REMOVED_KEYS)
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

/// Check the runtime file at the absolute `path` as `registry-render serve`
/// reads it, with no package, secret material, or listener (CFG-CHECK-1).
///
/// With `substitute` set, `${NAME}` expressions are filled from the process
/// environment and every value is checked. Without it, each expression is
/// checked by syntax and position only: the value checks of a member that
/// holds one are skipped, because they need the substituted text.
#[must_use]
pub fn check_runtime(path: &Path, substitute: bool) -> RuntimeCheck {
    read_runtime(path, substitute).1
}

/// Load and validate a runtime file through the shared loader, with the
/// process environment, as serve does at startup. Returns the runtime and
/// the `sha256:` digest of its effective configuration; a refusal carries
/// every finding, each positioned in the file and naming its fix.
pub fn load(path: &Path) -> Result<(RenderRuntime, String), RenderProblem> {
    match read_runtime(path, true) {
        (Some(loaded), _) => Ok((loaded.config, loaded.effective_digest)),
        (None, check) => {
            let detail = if check.unavailable {
                "the runtime configuration could not be read"
            } else {
                "the runtime configuration was refused"
            };
            Err(RenderProblem::new(ProblemKind::RuntimeInvalid, detail)
                .with_diagnostics(check.diagnostics))
        }
    }
}

/// The file read by the shared loader, then the members the loader cannot
/// judge checked: the bind, the package and secret provider blocks, the
/// caller key reference, and the audit destination. The configuration is
/// returned only when nothing was found.
fn read_runtime(
    path: &Path,
    substitute: bool,
) -> (Option<LoadedRuntimeConfig<RenderRuntime>>, RuntimeCheck) {
    let check = runtime_loader().check_offline::<RenderRuntime>(path, substitute, stand_in_for);
    let mut diagnostics = check.diagnostics.clone();
    if let Some(loaded) = &check.loaded {
        for finding in findings(&loaded.config) {
            let audit_deferred =
                finding.pointer.starts_with("/audit") && check.defers("/audit/destination");
            if !check.defers(&finding.pointer) && !audit_deferred {
                diagnostics.push(check.error_at(
                    RUNTIME_KIND,
                    finding.code,
                    &finding.pointer,
                    finding.message,
                    finding.action,
                ));
            }
        }
    }
    let unavailable = check.unavailable;
    let loaded = check.loaded.filter(|_| diagnostics.is_empty());
    (
        loaded,
        RuntimeCheck {
            diagnostics,
            unavailable,
        },
    )
}

/// One refusal of a member the shared loader accepted.
struct Finding {
    code: &'static str,
    pointer: String,
    message: String,
    action: String,
}

fn findings(runtime: &RenderRuntime) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !bind_allowed(runtime.listener.bind.socket_addr()) {
        findings.push(Finding {
            code: "render.runtime.public-bind",
            pointer: "/listener/bind".to_owned(),
            message: "listener.bind is not a loopback, private, or link-local address; Render \
                      never listens publicly or on all interfaces"
                .to_owned(),
            action: "Bind the private address your proxy forwards to; the proxy terminates TLS."
                .to_owned(),
        });
    }
    let blocks = [
        runtime.package.check(),
        runtime.secret_providers.check(),
        runtime
            .secret_providers
            .check_reference("auth.apiKeyRef", &runtime.auth.api_key_ref),
    ];
    findings.extend(
        blocks
            .iter()
            .filter_map(|result| result.as_ref().err())
            .map(block_finding),
    );
    if let Err(error) = runtime.audit.settings() {
        findings.push(audit_finding(&error));
    }
    findings
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
        "/audit/destination" => "file",
        "/audit/path" => "/audit.jsonl",
        _ => registry_platform_config::DEFAULT_STAND_IN,
    }
}

fn pointer_of(dotted: &str) -> String {
    dotted
        .split('.')
        .map(|segment| format!("/{}", escape_pointer_segment(segment)))
        .collect()
}

/// The code and fix for a shared package or secret provider refusal.
fn block_finding(error: &ConfigBlockError) -> Finding {
    let (code, action) = match error.kind() {
        ConfigBlockErrorKind::RelativePath => (
            "render.runtime.relative-path",
            "Write the path as an absolute path with no `.` or `..` segment.",
        ),
        ConfigBlockErrorKind::InvalidDigest => (
            "render.runtime.invalid-package-digest",
            "Write package.expectedDigest as the `sha256:` digest `registry-render package` \
             printed, or remove it.",
        ),
        ConfigBlockErrorKind::NoSecretProvider => (
            "render.runtime.no-secret-provider",
            "Declare secretProviders.file with an absolute root, \
             secretProviders.environment: {}, or both.",
        ),
        ConfigBlockErrorKind::InvalidSecretReference => (
            "render.runtime.invalid-secret-reference",
            "Write the reference as secret:file/<name> or secret:env/<NAME>.",
        ),
        ConfigBlockErrorKind::SecretProviderDisabled => (
            "render.runtime.undeclared-secret-provider",
            "Declare the provider the message names under secretProviders, or reference a \
             declared one.",
        ),
        _ => (
            "render.runtime.invalid-block",
            "Correct the member as the message describes.",
        ),
    };
    Finding {
        code,
        pointer: pointer_of(error.field()),
        message: error.to_string(),
        action: action.to_owned(),
    }
}

/// The code, position, and fix for a refusal of the audit block, under the
/// member names this file uses.
fn audit_finding(error: &AuditDestinationError) -> Finding {
    let finding = |code, pointer: &str, message: String, action: &str| Finding {
        code,
        pointer: pointer.to_owned(),
        message,
        action: action.to_owned(),
    };
    match error {
        AuditDestinationError::MissingPath => finding(
            "render.runtime.missing-audit-path",
            "/audit",
            error.to_string(),
            "Declare audit.path as the absolute path of the active audit file, or set \
             audit.destination to stdout.",
        ),
        AuditDestinationError::FileOnlyField { field } => {
            let member = match *field {
                "retainDays" => "retentionDays",
                other => other,
            };
            finding(
                "render.runtime.file-only-audit-member",
                &format!("/audit/{member}"),
                format!("audit.{member} applies only when audit.destination is file"),
                "Remove the member, or set audit.destination to file.",
            )
        }
        AuditDestinationError::RelativePath
        | AuditDestinationError::InvalidPathComponent
        | AuditDestinationError::NoFileName
        | AuditDestinationError::FileNameTooLong { .. } => finding(
            "render.runtime.invalid-audit-path",
            "/audit/path",
            error.to_string(),
            "Write audit.path as an absolute file path with no `.` or `..` segment, ending in \
             a file name.",
        ),
        AuditDestinationError::PathNamesReservedCompanion {
            suffix, companion, ..
        } => finding(
            "render.runtime.invalid-audit-path",
            "/audit/path",
            format!(
                "audit.path ends in `{suffix}`, which names the {companion} of another audit \
                 stream"
            ),
            "Choose an audit file name without that ending.",
        ),
        AuditDestinationError::RetainDaysOutOfRange { maximum } => finding(
            "render.runtime.invalid-audit",
            "/audit/retentionDays",
            format!("audit.retentionDays must be between 1 and {maximum}"),
            "Write a number of days within the bounds.",
        ),
        _ => finding(
            "render.runtime.invalid-audit",
            "/audit",
            error.to_string(),
            "Correct the audit block as the message describes.",
        ),
    }
}

/// Verify the shared package envelope, apply the optional digest pin, then
/// bind the exact captured product bytes that rendering will consume.
pub fn load_package(runtime: &RenderRuntime) -> Result<crate::Bundle, RenderProblem> {
    let verified = runtime
        .package
        .verify_package(&package_limits(), "registry-render package")
        .map_err(package_problem)?;
    crate::Bundle::load_package(&runtime.package.root, &verified)
}

/// Product bounds for authored and deployed Render packages.
pub fn package_limits() -> registry_platform_config::package::PackageLimits {
    registry_platform_config::package::PackageLimits::default()
}

pub(crate) fn package_problem(
    error: registry_platform_config::package::PackageError,
) -> RenderProblem {
    use registry_platform_config::package::PackageErrorKind;

    let kind = match error.kind() {
        PackageErrorKind::SumFileMissing => ProblemKind::BundleUnsealed,
        PackageErrorKind::DigestMismatch(_) => ProblemKind::RuntimeInvalid,
        _ => ProblemKind::BundleTampered,
    };
    RenderProblem::new(kind, error.to_string())
}

fn invalid(message: impl Into<String>) -> RenderProblem {
    RenderProblem::new(ProblemKind::RuntimeInvalid, message)
}

/// Resolve a secret reference under the providers the runtime declares.
pub fn resolve_secret(runtime: &RenderRuntime, reference: &str) -> Result<Vec<u8>, RenderProblem> {
    let resolver = runtime
        .secret_providers
        .resolver()
        .map_err(|err| invalid(format!("secretProviders: {err}")))?;
    let secret = resolver
        .resolve(reference)
        .map_err(|err| invalid(format!("{err}")))?;
    Ok(secret.expose_secret().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    /// A canonical temporary directory: the loader refuses a path through a
    /// symbolic link, and the system temporary directory is one on some
    /// hosts.
    fn home() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("deployment home");
        let path = dir.path().canonicalize().expect("canonical home");
        (dir, path)
    }

    const HEAD: &str = "apiVersion: id.registrystack.org/formats/render/runtime/v1alpha1\nkind: RenderRuntimeConfig\n";

    fn minimal(home: &Path) -> String {
        format!(
            "{HEAD}listener:\n  bind: 127.0.0.1:8080\npackage:\n  root: /srv/render/package\nsecretProviders:\n  file:\n    root: {secrets}\nauth:\n  apiKeyRef: secret:file/api.key\naudit:\n  path: /var/lib/render/audit/render.jsonl\n",
            secrets = home.join("secrets").display(),
        )
    }

    fn load_text(home: &Path, text: &str) -> Result<RenderRuntime, RenderProblem> {
        let file = home.join("runtime.yaml");
        std::fs::write(&file, text).expect("runtime file");
        load(&file).map(|(runtime, _)| runtime)
    }

    /// The code and pointer of every finding of a refused file.
    fn codes(problem: &RenderProblem) -> Vec<(&str, &str)> {
        problem
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect()
    }

    fn refused(home: &Path, text: &str) -> RenderProblem {
        let problem = load_text(home, text).expect_err("the runtime file is refused");
        assert_eq!(problem.kind, ProblemKind::RuntimeInvalid);
        problem
    }

    #[test]
    fn the_runtime_configuration_is_read_through_the_shared_loader() {
        let (_dir, home) = home();
        let file = home.join("runtime.yaml");
        std::fs::write(&file, minimal(&home)).expect("runtime file");
        let (runtime, digest) = load(&file).expect("the minimal runtime loads");
        assert_eq!(runtime.listener.bind.socket_addr().port(), 8080);
        assert_eq!(runtime.package.root, PathBuf::from("/srv/render/package"));
        assert!(
            registry_platform_config::is_sha256_label(&digest),
            "{digest}"
        );

        let problem = refused(
            &home,
            &minimal(&home).replace(
                "apiVersion: id.registrystack.org/formats/render/runtime/v1alpha1",
                "apiVersion: render.registrystack.org/v1alpha1",
            ),
        );
        assert_eq!(
            codes(&problem),
            [("config.unsupported-api-version", "/apiVersion")]
        );
    }

    #[test]
    fn cfg_change_2_the_retired_api_version_names_every_rename() {
        let (_dir, home) = home();
        let problem = refused(
            &home,
            &minimal(&home).replace(
                "apiVersion: id.registrystack.org/formats/render/runtime/v1alpha1",
                "apiVersion: registry.registrystack.org/render-runtime/v1alpha1",
            ),
        );
        assert_eq!(
            codes(&problem),
            [("config.retired-api-version", "/apiVersion")]
        );
        let action = &problem.diagnostics[0].suggested_action;
        for rename in [
            "id.registrystack.org/formats/render/runtime/v1alpha1",
            "listener.shutdownGraceMilliseconds",
            "limits.maximumOutputBytes",
            "limits.maximumRequestBytes",
            "limits.maximumConcurrentRenders",
            "audit.retentionDays",
        ] {
            assert!(action.contains(rename), "{rename}: {action}");
        }
    }

    #[test]
    fn the_listener_bind_is_required() {
        let (_dir, home) = home();
        let text = minimal(&home).replace("listener:\n  bind: 127.0.0.1:8080\n", "");
        let problem = refused(&home, &text);
        assert_eq!(problem.diagnostics[0].code, "config.missing-key");
        assert!(
            problem.diagnostics[0].message.contains("listener"),
            "{:?}",
            problem.diagnostics
        );
    }

    #[test]
    fn cfg_change_2_removed_keys_name_their_replacements() {
        let (_dir, home) = home();
        let audit_path = "  path: /var/lib/render/audit/render.jsonl\n";
        for (text, pointer, replacement) in [
            (
                minimal(&home).replace("listener:\n  bind:", "server:\n  bind:"),
                "/server",
                "listener.bind",
            ),
            (
                minimal(&home).replace("package:\n  root:", "bundle:\n  path:"),
                "/bundle",
                "package.root",
            ),
            (
                minimal(&home).replace(
                    "  bind: 127.0.0.1:8080\n",
                    "  bind: 127.0.0.1:8080\n  shutdownGraceSeconds: 30\n",
                ),
                "/listener/shutdownGraceSeconds",
                "times 1000",
            ),
            (
                format!("{}limits:\n  maxOutputBytes: 1024\n", minimal(&home)),
                "/limits/maxOutputBytes",
                "limits.maximumOutputBytes",
            ),
            (
                format!("{}limits:\n  maxRequestBodyBytes: 1024\n", minimal(&home)),
                "/limits/maxRequestBodyBytes",
                "limits.maximumRequestBytes",
            ),
            (
                format!("{}limits:\n  maxConcurrency: 2\n", minimal(&home)),
                "/limits/maxConcurrency",
                "limits.maximumConcurrentRenders",
            ),
            (
                minimal(&home).replace(audit_path, "  directory: /var/lib/render/audit\n"),
                "/audit/directory",
                "audit.path",
            ),
            (
                minimal(&home).replace(
                    audit_path,
                    &format!("{audit_path}  integrityKeyRef: secret:file/audit.key\n"),
                ),
                "/audit/integrityKeyRef",
                "not hash-chained",
            ),
            (
                minimal(&home).replace(
                    audit_path,
                    &format!("{audit_path}  maxSegmentBytes: 67108864\n"),
                ),
                "/audit/maxSegmentBytes",
                "audit.rotateBytes",
            ),
            (
                minimal(&home).replace(audit_path, &format!("{audit_path}  retainDays: 30\n")),
                "/audit/retainDays",
                "audit.retentionDays",
            ),
        ] {
            let problem = refused(&home, &text);
            let removed = problem
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == "config.removed-key")
                .unwrap_or_else(|| panic!("{pointer}: {:?}", problem.diagnostics));
            assert_eq!(removed.path, pointer);
            assert!(
                removed.suggested_action.contains(replacement),
                "{pointer}: {}",
                removed.suggested_action
            );
        }
    }

    #[test]
    fn package_and_audit_paths_must_be_absolute() {
        let (_dir, home) = home();
        for (text, expected) in [
            (
                minimal(&home).replace("root: /srv/render/package", "root: ../package"),
                ("render.runtime.relative-path", "/package/root"),
            ),
            (
                minimal(&home).replace(
                    "path: /var/lib/render/audit/render.jsonl",
                    "path: audit/render.jsonl",
                ),
                ("render.runtime.invalid-audit-path", "/audit/path"),
            ),
        ] {
            assert_eq!(codes(&refused(&home, &text)), [expected]);
        }
    }

    #[test]
    fn a_secret_reference_must_name_a_declared_provider() {
        let (_dir, home) = home();
        let text = minimal(&home).replace(
            "apiKeyRef: secret:file/api.key",
            "apiKeyRef: secret:env/RENDER_API_KEY",
        );
        let problem = refused(&home, &text);
        assert_eq!(
            codes(&problem),
            [(
                "render.runtime.undeclared-secret-provider",
                "/auth/apiKeyRef"
            )]
        );
        assert!(
            problem.diagnostics[0]
                .message
                .contains("secretProviders.environment"),
            "{}",
            problem.diagnostics[0].message
        );

        let text = text.replace(
            "secretProviders:\n",
            "secretProviders:\n  environment: {}\n",
        );
        load_text(&home, &text).expect("the declared environment provider admits the reference");

        let text = minimal(&home).replace(
            &format!(
                "secretProviders:\n  file:\n    root: {}\n",
                home.join("secrets").display()
            ),
            "secretProviders: {}\n",
        );
        let problem = refused(&home, &text);
        assert_eq!(
            codes(&problem),
            [
                ("render.runtime.no-secret-provider", "/secretProviders"),
                (
                    "render.runtime.undeclared-secret-provider",
                    "/auth/apiKeyRef"
                ),
            ]
        );
    }

    #[test]
    fn environment_expressions_substitute_values_but_never_secret_references() {
        let (_dir, home) = home();
        let file = home.join("runtime.yaml");
        std::fs::write(
            &file,
            minimal(&home).replace(
                "root: /srv/render/package",
                "root: ${RENDER_PACKAGE_ROOT:-/srv/render/default}",
            ),
        )
        .expect("runtime file");
        let (runtime, _) = load(&file).expect("a defaulted expression loads");
        assert_eq!(runtime.package.root, PathBuf::from("/srv/render/default"));

        let text = minimal(&home).replace(
            "apiKeyRef: secret:file/api.key",
            "apiKeyRef: ${RENDER_API_KEY_REF:-secret:file/api.key}",
        );
        let problem = refused(&home, &text);
        assert_eq!(problem.diagnostics[0].path, "/auth/apiKeyRef");
    }

    #[test]
    fn secrets_resolve_under_the_declared_file_root_only() {
        let (_dir, home) = home();
        let secrets = home.join("secrets");
        std::fs::create_dir_all(&secrets).expect("secret root");
        write_secret(&secrets.join("api.key"), b"from-the-declared-root");
        // A file beside the runtime file is not a secret root.
        write_secret(&home.join("audit.key"), b"beside-the-runtime-file");
        let runtime = load_text(&home, &minimal(&home)).expect("runtime loads");
        assert_eq!(
            resolve_secret(&runtime, &runtime.auth.api_key_ref).expect("declared root"),
            b"from-the-declared-root"
        );
        resolve_secret(&runtime, "secret:file/audit.key")
            .expect_err("a file outside the declared root does not resolve");
    }

    fn with_audit(home: &Path, audit: &str) -> String {
        minimal(home).replace("  path: /var/lib/render/audit/render.jsonl\n", audit)
    }

    #[test]
    fn the_audit_block_takes_the_shared_destination_shape() {
        let (_dir, home) = home();
        let file = load_text(
            &home,
            &with_audit(
                &home,
                "  path: /a/render.jsonl\n  rotateBytes: 1048576\n  retentionDays: 30\n",
            ),
        )
        .expect("a file destination with rotation and retention loads");
        match file.audit.destination().expect("destination") {
            AuditDestination::File(file) => {
                assert_eq!(file.path(), Path::new("/a/render.jsonl"));
                assert_eq!(file.rotate_bytes(), 1_048_576);
                assert_eq!(file.retain_days(), 30);
            }
            AuditDestination::Stdout | AuditDestination::Stderr => {
                panic!("file is the default destination")
            }
        }
        let stdout = load_text(&home, &with_audit(&home, "  destination: stdout\n"))
            .expect("a stdout destination loads");
        assert_eq!(
            stdout.audit.destination().expect("destination"),
            AuditDestination::Stdout
        );
    }

    #[test]
    fn an_audit_block_outside_the_shared_shape_is_refused() {
        let (_dir, home) = home();
        for (audit, code, pointer) in [
            (
                "  destination: file\n",
                "render.runtime.missing-audit-path",
                "/audit",
            ),
            (
                "  path: \"\"\n",
                "render.runtime.invalid-audit-path",
                "/audit/path",
            ),
            (
                "  destination: stdout\n  path: /a/render.jsonl\n",
                "render.runtime.file-only-audit-member",
                "/audit/path",
            ),
            (
                "  destination: stdout\n  retentionDays: 7\n",
                "render.runtime.file-only-audit-member",
                "/audit/retentionDays",
            ),
            (
                "  path: /a/render.jsonl\n  rotateBytes: 1024\n",
                "config.out-of-range",
                "/audit/rotateBytes",
            ),
            (
                "  path: /a/render.jsonl\n  retentionDays: 0\n",
                "config.out-of-range",
                "/audit/retentionDays",
            ),
            (
                "  path: /a/render.jsonl\n  retentionDays: 36501\n",
                "config.out-of-range",
                "/audit/retentionDays",
            ),
            (
                "  path: /a/../render.jsonl\n",
                "render.runtime.invalid-audit-path",
                "/audit/path",
            ),
        ] {
            let problem = refused(&home, &with_audit(&home, audit));
            assert_eq!(codes(&problem), [(code, pointer)], "{audit}");
        }
        // The message names the member as this file spells it.
        let problem = refused(
            &home,
            &with_audit(&home, "  destination: stdout\n  retentionDays: 7\n"),
        );
        assert_eq!(
            problem.diagnostics[0].message,
            "audit.retentionDays applies only when audit.destination is file"
        );
    }

    fn write_secret(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, bytes).expect("secret file");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("secret mode");
    }

    #[test]
    fn loopback_private_and_link_local_binds_are_allowed() {
        for bind in [
            "127.0.0.1:8080",
            "10.0.0.5:8080",
            "192.168.1.10:8080",
            "172.16.0.1:8080",
            "169.254.7.7:8080",
            "[::1]:8080",
            "[fe80::1]:8080",
            "[fd00::5]:8080",
        ] {
            let addr: SocketAddr = bind.parse().unwrap();
            validate_bind(addr).unwrap_or_else(|err| panic!("{bind} must be allowed: {err}"));
        }
    }

    #[test]
    fn a_public_bind_in_the_file_is_refused_at_its_value() {
        let (_dir, home) = home();
        let problem = refused(
            &home,
            &minimal(&home).replace("bind: 127.0.0.1:8080", "bind: 0.0.0.0:8080"),
        );
        assert_eq!(
            codes(&problem),
            [("render.runtime.public-bind", "/listener/bind")]
        );
        let diagnostic = &problem.diagnostics[0];
        let source = diagnostic.source.as_ref().expect("positioned");
        assert_eq!((source.line, source.column), (Some(4), Some(9)));
        // CFG-SEC-3: the finding names the member, never its value.
        assert!(
            !diagnostic.message.contains("0.0.0.0"),
            "{}",
            diagnostic.message
        );
    }

    #[test]
    fn cfg_qty_4_shutdown_grace_outside_its_bounds_is_refused() {
        // A grace under a second drops renders in flight on SIGTERM, and a
        // grace past the hour overflows the bounded wait the shutdown path
        // computes.
        let (_dir, home) = home();
        for grace in ["0", "999", "3600001", "10000000000000000000"] {
            let text = minimal(&home).replace(
                "  bind: 127.0.0.1:8080\n",
                &format!("  bind: 127.0.0.1:8080\n  shutdownGraceMilliseconds: {grace}\n"),
            );
            assert_eq!(
                codes(&refused(&home, &text)),
                [("config.out-of-range", "/listener/shutdownGraceMilliseconds")],
                "grace {grace}"
            );
        }
    }

    #[test]
    fn shutdown_grace_at_the_range_ends_is_accepted() {
        let (_dir, home) = home();
        for grace in [1_000, 3_600_000] {
            let text = minimal(&home).replace(
                "  bind: 127.0.0.1:8080\n",
                &format!("  bind: 127.0.0.1:8080\n  shutdownGraceMilliseconds: {grace}\n"),
            );
            let runtime = load_text(&home, &text).expect("grace at the range end loads");
            assert_eq!(
                runtime.listener.shutdown_grace(),
                Duration::from_millis(grace)
            );
        }
        let runtime = load_text(&home, &minimal(&home)).expect("runtime loads");
        assert_eq!(runtime.listener.shutdown_grace(), Duration::from_secs(30));
    }

    #[test]
    fn cfg_qty_4_every_limit_is_bounded() {
        let (_dir, home) = home();
        for (limit, value) in [
            ("renderTimeoutSeconds", "0"),
            ("renderTimeoutSeconds", "3601"),
            ("maximumOutputBytes", "0"),
            ("maximumOutputBytes", "8388609"),
            ("maximumRequestBytes", "0"),
            ("maximumRequestBytes", "67108865"),
            ("maximumConcurrentRenders", "0"),
            ("maximumConcurrentRenders", "65"),
        ] {
            let text = format!("{}limits:\n  {limit}: {value}\n", minimal(&home));
            let pointer = format!("/limits/{limit}");
            assert_eq!(
                codes(&refused(&home, &text)),
                [("config.out-of-range", pointer.as_str())],
                "{limit} {value}"
            );
        }
        let text = format!(
            "{}limits:\n  renderTimeoutSeconds: 3600\n  maximumOutputBytes: 8388608\n  maximumRequestBytes: 67108864\n  maximumConcurrentRenders: 64\n",
            minimal(&home)
        );
        let limits = load_text(&home, &text)
            .expect("limits at their maximum load")
            .limits;
        assert_eq!(limits.render_timeout(), Duration::from_secs(3600));
        assert_eq!(limits.output_bytes(), 8 * 1024 * 1024);
        assert_eq!(limits.request_bytes(), 64 * 1024 * 1024);
        assert_eq!(limits.concurrent_renders(), 64);
    }

    #[test]
    fn omitted_limits_take_their_defaults() {
        let (_dir, home) = home();
        let limits = load_text(&home, &minimal(&home))
            .expect("runtime loads")
            .limits;
        assert_eq!(limits.render_timeout(), Duration::from_secs(20));
        assert_eq!(
            limits.output_bytes(),
            crate::render::DEFAULT_MAX_OUTPUT_BYTES
        );
        assert_eq!(limits.request_bytes(), 8 * 1024 * 1024);
        assert!((1..=8).contains(&limits.concurrent_renders()));
    }

    #[test]
    fn cfg_diag_5_every_finding_is_reported_in_one_run() {
        let (_dir, home) = home();
        let text = minimal(&home)
            .replace("bind: 127.0.0.1:8080", "bind: 0.0.0.0:8080")
            .replace("root: /srv/render/package", "root: package")
            .replace(
                "apiKeyRef: secret:file/api.key",
                "apiKeyRef: secret:env/KEY",
            )
            .replace(
                "  path: /var/lib/render/audit/render.jsonl\n",
                "  destination: file\n",
            );
        let problem = refused(&home, &text);
        assert_eq!(
            codes(&problem),
            [
                ("render.runtime.public-bind", "/listener/bind"),
                ("render.runtime.relative-path", "/package/root"),
                (
                    "render.runtime.undeclared-secret-provider",
                    "/auth/apiKeyRef"
                ),
                ("render.runtime.missing-audit-path", "/audit"),
            ]
        );
        // Serve prints the same lines on standard error (CFG-DIAG-2).
        let human = problem.render_human();
        let file = home.join("runtime.yaml");
        assert!(
            human.starts_with(
                "registry-render: runtime-invalid: the runtime configuration was refused\n"
            ),
            "{human}"
        );
        assert!(
            human.contains(&format!(
                "error[render.runtime.public-bind] {}:4:9 /listener/bind\n",
                file.display()
            )),
            "{human}"
        );
        assert!(
            human.ends_with("4 errors, 0 warnings in 1 file\n"),
            "{human}"
        );
    }

    #[test]
    fn cfg_check_1_an_expression_is_checked_by_position_without_the_environment() {
        let (_dir, home) = home();
        let file = home.join("runtime.yaml");
        std::fs::write(
            &file,
            minimal(&home)
                .replace("127.0.0.1:8080", "\"${RENDER_CHECK_UNSET_BIND}\"")
                .replace(
                    "/var/lib/render/audit/render.jsonl",
                    "${RENDER_CHECK_UNSET_AUDIT}",
                ),
        )
        .expect("runtime file");
        let offline = check_runtime(&file, false);
        assert!(offline.diagnostics.is_empty(), "{:?}", offline.diagnostics);
        assert!(!offline.unavailable);

        // Substituting from the environment checks the values, and an unset
        // variable is reported where it is written.
        let substituted = check_runtime(&file, true);
        assert_eq!(
            substituted
                .diagnostics
                .first()
                .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str())),
            Some(("config.substitution", "/listener/bind"))
        );
    }

    #[test]
    fn cfg_check_1_an_unreadable_file_is_an_operational_failure() {
        let (_dir, home) = home();
        let check = check_runtime(&home.join("missing.yaml"), false);
        assert!(check.unavailable);
        assert_eq!(check.diagnostics.len(), 1);

        let problem = load(&home.join("missing.yaml")).expect_err("no file");
        assert_eq!(
            problem.detail,
            "the runtime configuration could not be read"
        );
    }

    #[test]
    fn public_and_unspecified_binds_are_refused() {
        for bind in [
            "0.0.0.0:8080",
            "8.8.8.8:8080",
            "203.0.113.9:8080",
            "[::]:8080",
            "[2001:db8::1]:8080",
        ] {
            let addr: SocketAddr = bind.parse().unwrap();
            let problem = validate_bind(addr).expect_err(bind);
            assert_eq!(problem.kind, ProblemKind::RuntimeInvalid, "{bind}");
            assert!(
                problem.detail.contains("listener.bind"),
                "{}",
                problem.detail
            );
        }
    }
}
