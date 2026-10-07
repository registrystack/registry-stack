//! The serve runtime: one strict YAML file with everything a deployment
//! owns: listener, verified bundle package, secret providers, caller key,
//! limits, audit. Nothing here can override governed (bundle) behavior.
//!
//! The file is read through the shared Registry Stack runtime configuration
//! loader, so its envelope, size bound, path rules, `${VAR}` substitution,
//! and secret provider declarations match every other runtime.

use std::path::{Path, PathBuf};

use registry_platform_audit::{AuditDestination, AuditDestinationKind};
use registry_platform_config::{
    ListenerBind, PackageConfig, RemovedKey, RuntimeConfigLoader, RuntimeEnvelope,
    SecretProvidersConfig,
};
use serde::Deserialize;

use crate::problem::{ProblemKind, RenderProblem};

pub const RUNTIME_API_VERSION: &str = "registry.registrystack.org/render-runtime/v1alpha1";
pub const RUNTIME_KIND: &str = "RenderRuntimeConfig";

const RENDER_RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: RUNTIME_API_VERSION,
    kind: RUNTIME_KIND,
};

/// Keys an earlier runtime file carried, each refused with its replacement.
const RENDER_REMOVED_KEYS: &[RemovedKey] = &[
    RemovedKey {
        path: "server",
        replacement: "declare listener.bind and listener.shutdownGraceSeconds instead",
    },
    RemovedKey {
        path: "bundle",
        replacement: "declare package.root as the absolute path of the package directory",
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
];

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListenerRuntime {
    /// Loopback or private address to listen on. Public and all-interfaces
    /// binds are refused at startup, see [`validate_bind`]. TLS is the
    /// proxy's job, not Render's.
    pub bind: ListenerBind,
    /// Grace period for in-flight renders at shutdown.
    #[serde(default = "default_shutdown_grace_seconds")]
    pub shutdown_grace_seconds: u64,
}

/// Render never listens on a public address: TLS termination and network
/// position belong to the deployment's proxy. Loopback, private, and
/// link-local addresses pass; unspecified (all interfaces) and public
/// addresses are refused with a named startup problem, an explicit refusal
/// instead of an accidental exposure.
pub fn validate_bind(addr: std::net::SocketAddr) -> Result<(), RenderProblem> {
    let allowed = match addr {
        std::net::SocketAddr::V4(a) => {
            let ip = a.ip();
            ip.is_loopback() || ip.is_private() || ip.is_link_local()
        }
        std::net::SocketAddr::V6(a) => {
            let ip = a.ip();
            ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
        }
    };
    if allowed {
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

/// The longest grace a runtime may declare. Shutdown waits the grace for
/// renders in flight and then the same again for connections, so the bound
/// keeps that sum representable as well as operationally sane.
pub const MAX_SHUTDOWN_GRACE_SECONDS: u64 = 3600;

fn default_shutdown_grace_seconds() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthRuntime {
    /// Secret reference to the caller API key, under a declared provider.
    pub api_key_ref: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LimitsRuntime {
    /// Wall-clock budget per render; the worker is killed at this bound.
    #[serde(default = "default_render_timeout_seconds")]
    pub render_timeout_seconds: u64,
    /// Hard ceiling for the produced PDF.
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: usize,
    /// Request body ceiling (data + base64 assets). The httpsec default is
    /// 1 MiB; renders with photos need a conscious, bounded raise.
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
    /// Concurrent renders. Default: CPU count, capped.
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: usize,
}

impl Default for LimitsRuntime {
    fn default() -> Self {
        Self {
            render_timeout_seconds: default_render_timeout_seconds(),
            max_output_bytes: default_max_output_bytes(),
            max_request_body_bytes: default_max_request_body_bytes(),
            max_concurrency: default_max_concurrency(),
        }
    }
}

pub fn default_render_timeout_seconds() -> u64 {
    20
}
pub fn default_max_output_bytes() -> usize {
    crate::render::DEFAULT_MAX_OUTPUT_BYTES
}
pub fn default_max_request_body_bytes() -> usize {
    8 * 1024 * 1024
}
pub fn default_max_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().min(8))
        .unwrap_or(2)
}

/// The audit block every Registry Stack product shares: a `file` (the
/// default) or `stdout` destination, with rotation and retention for a file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditRuntime {
    /// Where audit lines go: `file` or `stdout`.
    #[serde(default)]
    pub destination: AuditDestinationKind,
    /// The absolute path of the active audit file, for a `file` destination.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Size at which the active file rotates, for a `file` destination.
    #[serde(default)]
    pub rotate_bytes: Option<u64>,
    /// Days a rotated file is kept, for a `file` destination.
    #[serde(default)]
    pub retain_days: Option<u32>,
}

impl AuditRuntime {
    /// The validated destination the audit writer opens.
    pub fn destination(&self) -> Result<AuditDestination, RenderProblem> {
        AuditDestination::from_settings(
            self.destination,
            self.path.clone(),
            self.rotate_bytes,
            self.retain_days,
        )
        .map_err(|err| RenderProblem::new(ProblemKind::RuntimeInvalid, err.to_string()))
    }
}

fn invalid(message: impl Into<String>) -> RenderProblem {
    RenderProblem::new(ProblemKind::RuntimeInvalid, message)
}

/// Load and validate a runtime file through the shared loader. Returns the
/// runtime and the `sha256:` digest of its effective configuration.
pub fn load(path: &Path) -> Result<(RenderRuntime, String), RenderProblem> {
    let loaded = RuntimeConfigLoader::new(RENDER_RUNTIME_ENVELOPE)
        .removed_keys(RENDER_REMOVED_KEYS)
        .load::<RenderRuntime>(path)
        .map_err(|error| invalid(error.to_string()))?;
    let runtime = loaded.config;
    let in_file = |message: String| invalid(format!("{}: {message}", path.display()));
    runtime
        .package
        .check()
        .map_err(|error| in_file(error.to_string()))?;
    runtime
        .secret_providers
        .check()
        .map_err(|error| in_file(error.to_string()))?;
    runtime
        .secret_providers
        .check_reference("auth.apiKeyRef", &runtime.auth.api_key_ref)
        .map_err(|error| in_file(error.to_string()))?;
    runtime
        .audit
        .destination()
        .map_err(|error| in_file(error.detail))?;
    if runtime.limits.max_output_bytes > crate::render::DEFAULT_MAX_OUTPUT_BYTES {
        return Err(invalid(format!(
            "maxOutputBytes {} exceeds the hard ceiling {}",
            runtime.limits.max_output_bytes,
            crate::render::DEFAULT_MAX_OUTPUT_BYTES
        )));
    }
    if runtime.limits.max_concurrency == 0 || runtime.limits.max_concurrency > 64 {
        return Err(invalid("maxConcurrency must be between 1 and 64"));
    }
    if runtime.limits.max_request_body_bytes > 64 * 1024 * 1024 {
        return Err(invalid(
            "maxRequestBodyBytes exceeds the 64 MiB hard ceiling",
        ));
    }
    // Zero would drop renders in flight the moment SIGTERM arrives; a value
    // past the hour is not a deployment intent, and the bounded wait the
    // shutdown path computes from it must stay representable.
    if !(1..=MAX_SHUTDOWN_GRACE_SECONDS).contains(&runtime.listener.shutdown_grace_seconds) {
        return Err(invalid(format!(
            "listener.shutdownGraceSeconds must be between 1 and {MAX_SHUTDOWN_GRACE_SECONDS}, found {}",
            runtime.listener.shutdown_grace_seconds
        )));
    }
    Ok((runtime, loaded.effective_digest))
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

    const HEAD: &str = "apiVersion: registry.registrystack.org/render-runtime/v1alpha1\nkind: RenderRuntimeConfig\n";

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

        let error = load_text(
            &home,
            &minimal(&home).replace(
                "apiVersion: registry.registrystack.org/render-runtime/v1alpha1",
                "apiVersion: render.registrystack.org/v1alpha1",
            ),
        )
        .expect_err("the retired envelope is refused");
        assert!(
            error
                .detail
                .contains("it reads `registry.registrystack.org/render-runtime/v1alpha1`"),
            "{}",
            error.detail
        );
    }

    #[test]
    fn the_listener_bind_is_required() {
        let (_dir, home) = home();
        let text = minimal(&home).replace("listener:\n  bind: 127.0.0.1:8080\n", "");
        let error = load_text(&home, &text).expect_err("no listener");
        assert_eq!(error.kind, ProblemKind::RuntimeInvalid);
        assert!(error.detail.contains("listener"), "{}", error.detail);
    }

    #[test]
    fn removed_keys_name_their_replacements() {
        let (_dir, home) = home();
        for (text, key, replacement) in [
            (
                minimal(&home).replace("listener:\n  bind:", "server:\n  bind:"),
                "server",
                "listener.bind",
            ),
            (
                minimal(&home).replace("package:\n  root:", "bundle:\n  path:"),
                "bundle",
                "package.root",
            ),
            (
                minimal(&home).replace("  path: /var/lib/render/audit/render.jsonl\n", "  directory: /var/lib/render/audit\n"),
                "audit.directory",
                "audit.path",
            ),
            (
                minimal(&home).replace(
                    "  path: /var/lib/render/audit/render.jsonl\n",
                    "  path: /var/lib/render/audit/render.jsonl\n  integrityKeyRef: secret:file/audit.key\n",
                ),
                "audit.integrityKeyRef",
                "not hash-chained",
            ),
            (
                minimal(&home).replace("  path: /var/lib/render/audit/render.jsonl\n", "  path: /var/lib/render/audit/render.jsonl\n  maxSegmentBytes: 67108864\n"),
                "audit.maxSegmentBytes",
                "audit.rotateBytes",
            ),
        ] {
            let error = load_text(&home, &text).expect_err(key);
            let pointer = key.replace('.', "/");
            let member = key.rsplit('.').next().unwrap_or(key);
            assert!(
                error
                    .detail
                    .contains(&format!("/{pointer}\n  `{member}` is no longer accepted"))
                    && error.detail.contains(replacement),
                "{key}: {}",
                error.detail
            );
        }
    }

    #[test]
    fn package_and_audit_paths_must_be_absolute() {
        let (_dir, home) = home();
        for (text, field) in [
            (
                minimal(&home).replace("root: /srv/render/package", "root: ../package"),
                "package.root",
            ),
            (
                minimal(&home).replace(
                    "path: /var/lib/render/audit/render.jsonl",
                    "path: audit/render.jsonl",
                ),
                "audit.path",
            ),
        ] {
            let error = load_text(&home, &text).expect_err(field);
            assert!(error.detail.contains(field), "{field}: {}", error.detail);
        }
    }

    #[test]
    fn a_secret_reference_must_name_a_declared_provider() {
        let (_dir, home) = home();
        let text = minimal(&home).replace(
            "apiKeyRef: secret:file/api.key",
            "apiKeyRef: secret:env/RENDER_API_KEY",
        );
        let error = load_text(&home, &text).expect_err("environment provider not declared");
        assert!(error.detail.contains("auth.apiKeyRef"), "{}", error.detail);
        assert!(
            error.detail.contains("secretProviders.environment"),
            "{}",
            error.detail
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
        let error = load_text(&home, &text).expect_err("no provider declared");
        assert!(error.detail.contains("secretProviders"), "{}", error.detail);
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
        let error = load_text(&home, &text).expect_err("an expression in a *Ref field is refused");
        assert!(error.detail.contains("/auth/apiKeyRef"), "{}", error.detail);
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
                "  path: /a/render.jsonl\n  rotateBytes: 1048576\n  retainDays: 30\n",
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
        for (audit, expected) in [
            ("  destination: file\n", "audit.path is required"),
            ("  path: \"\"\n", "audit.path"),
            (
                "  destination: stdout\n  path: /a/render.jsonl\n",
                "audit.path applies only",
            ),
            (
                "  path: /a/render.jsonl\n  rotateBytes: 1024\n",
                "audit.rotateBytes must be between",
            ),
            (
                "  path: /a/render.jsonl\n  retainDays: 0\n",
                "audit.retainDays must be between",
            ),
            ("  path: /a/../render.jsonl\n", "audit.path"),
        ] {
            let err = load_text(&home, &with_audit(&home, audit)).expect_err(audit);
            assert_eq!(err.kind, ProblemKind::RuntimeInvalid, "{audit}");
            assert!(err.detail.contains(expected), "{audit}: {}", err.detail);
        }
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
    fn shutdown_grace_outside_the_supported_range_is_refused() {
        // A zero grace drops renders in flight on SIGTERM, and a grace past
        // the hour overflows the bounded wait the shutdown path computes.
        let (_dir, home) = home();
        for grace in ["0", "3601", "10000000000000000000"] {
            let text = minimal(&home).replace(
                "  bind: 127.0.0.1:8080\n",
                &format!("  bind: 127.0.0.1:8080\n  shutdownGraceSeconds: {grace}\n"),
            );
            let err = load_text(&home, &text).expect_err("out-of-range grace must be refused");
            assert_eq!(err.kind, ProblemKind::RuntimeInvalid, "grace {grace}");
            assert!(
                err.detail.contains("shutdownGraceSeconds"),
                "grace {grace}: {}",
                err.detail
            );
        }
    }

    #[test]
    fn shutdown_grace_at_the_range_ends_is_accepted() {
        let (_dir, home) = home();
        for grace in [1, 3600] {
            let text = minimal(&home).replace(
                "  bind: 127.0.0.1:8080\n",
                &format!("  bind: 127.0.0.1:8080\n  shutdownGraceSeconds: {grace}\n"),
            );
            let runtime = load_text(&home, &text).expect("grace at the range end loads");
            assert_eq!(runtime.listener.shutdown_grace_seconds, grace);
        }
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
