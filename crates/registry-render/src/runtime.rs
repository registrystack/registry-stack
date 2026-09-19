//! The serve runtime: one strict YAML file with everything a deployment
//! owns — bind address, sealed bundle path, caller key, limits, audit.
//! Nothing here can override governed (bundle) behavior.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::problem::{ProblemKind, RenderProblem};

pub const RUNTIME_API_VERSION: &str = "render.registrystack.org/v1alpha1";
pub const RUNTIME_KIND: &str = "RenderRuntime";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RenderRuntime {
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    pub server: ServerRuntime,
    pub bundle: BundleRuntime,
    pub auth: AuthRuntime,
    #[serde(default)]
    pub limits: LimitsRuntime,
    pub audit: AuditRuntime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServerRuntime {
    /// Loopback or private address to listen on; defaults to loopback.
    /// Public and all-interfaces binds are refused at startup — see
    /// [`validate_bind`]. TLS is the proxy's job, not Render's.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Grace period for in-flight renders at shutdown.
    #[serde(default = "default_shutdown_grace_seconds")]
    pub shutdown_grace_seconds: u64,
}

/// The default listener: loopback, fixed port. Deployments behind a proxy
/// set their own private address explicitly.
pub fn default_bind() -> String {
    "127.0.0.1:8080".to_owned()
}

impl Default for ServerRuntime {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            shutdown_grace_seconds: default_shutdown_grace_seconds(),
        }
    }
}

/// Render never listens on a public address: TLS termination and network
/// position belong to the deployment's proxy. Loopback, private, and
/// link-local addresses pass; unspecified (all interfaces) and public
/// addresses are refused with a named startup problem — an explicit refusal
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
                "server.bind {addr} is not a loopback or private address; Render never \
                 listens publicly or on all interfaces — terminate TLS and position the \
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BundleRuntime {
    /// Path to a sealed bundle directory. Relative paths anchor to the
    /// runtime file's directory (see [`load`]), not the working directory.
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthRuntime {
    /// `secret:file/…` or `secret:env/…` reference to the caller API key.
    pub api_key_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditRuntime {
    /// Directory for the sealed, hash-chained JSONL ledger. Relative paths
    /// anchor to the runtime file's directory (see [`load`]).
    pub directory: PathBuf,
    /// `secret:file/…` or `secret:env/…` reference to the chain integrity
    /// key (>= 32 bytes).
    pub integrity_key_ref: String,
    /// Sealed segment size before rotation.
    #[serde(default = "default_max_segment_bytes")]
    pub max_segment_bytes: u64,
}

pub fn default_max_segment_bytes() -> u64 {
    64 * 1024 * 1024
}

/// Load and validate a runtime file, expanding bounded `${VAR}` references.
/// Relative `bundle.path` and `audit.directory` values are anchored to the
/// runtime file's directory — the same anchor `secret:file/…` refs use — so
/// one runtime file behaves identically regardless of the working directory
/// it is loaded from. Returns the runtime and its canonical sha256 config id.
pub fn load(path: &Path) -> Result<(RenderRuntime, String), RenderProblem> {
    let raw = std::fs::read_to_string(path).map_err(|err| {
        RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!("cannot read runtime {}: {err}", path.display()),
        )
    })?;
    let expanded = registry_platform_config::expand_config_env_vars(&raw)
        .map_err(|err| RenderProblem::new(ProblemKind::RuntimeInvalid, format!("{err}")))?;
    let mut runtime: RenderRuntime = serde_norway::from_str(&expanded).map_err(|err| {
        RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!("runtime YAML invalid: {err}"),
        )
    })?;
    if runtime.api_version != RUNTIME_API_VERSION {
        return Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!(
                "runtime apiVersion must be {RUNTIME_API_VERSION}, found {}",
                runtime.api_version
            ),
        ));
    }
    if runtime.kind != RUNTIME_KIND {
        return Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!(
                "runtime kind must be {RUNTIME_KIND}, found {}",
                runtime.kind
            ),
        ));
    }
    if runtime.limits.max_output_bytes > crate::render::DEFAULT_MAX_OUTPUT_BYTES {
        return Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!(
                "maxOutputBytes {} exceeds the hard ceiling {}",
                runtime.limits.max_output_bytes,
                crate::render::DEFAULT_MAX_OUTPUT_BYTES
            ),
        ));
    }
    if runtime.limits.max_concurrency == 0 || runtime.limits.max_concurrency > 64 {
        return Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            "maxConcurrency must be between 1 and 64",
        ));
    }
    if runtime.limits.max_request_body_bytes > 64 * 1024 * 1024 {
        return Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            "maxRequestBodyBytes exceeds the 64 MiB hard ceiling",
        ));
    }
    // Zero would drop renders in flight the moment SIGTERM arrives; a value
    // past the hour is not a deployment intent, and the bounded wait the
    // shutdown path computes from it must stay representable.
    if !(1..=MAX_SHUTDOWN_GRACE_SECONDS).contains(&runtime.server.shutdown_grace_seconds) {
        return Err(RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!(
                "shutdownGraceSeconds must be between 1 and {MAX_SHUTDOWN_GRACE_SECONDS}, found {}",
                runtime.server.shutdown_grace_seconds
            ),
        ));
    }
    let anchor = runtime_anchor(path);
    runtime.bundle.path = anchored(&anchor, &runtime.bundle.path);
    runtime.audit.directory = anchored(&anchor, &runtime.audit.directory);
    let id = crate::hash::sha256_hex(expanded.as_bytes());
    Ok((runtime, id))
}

/// The directory runtime-relative values anchor to: the runtime file's own
/// directory, canonicalized when possible. A bare filename anchors to the
/// current directory (its parent is empty).
fn runtime_anchor(runtime_path: &Path) -> PathBuf {
    let parent = runtime_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));
    std::fs::canonicalize(&parent).unwrap_or(parent)
}

/// Join a configured path onto the anchor when relative, collapsing `.` and
/// `..` lexically so anchored paths stay readable in problems and logs.
/// Absolute paths pass through verbatim.
fn anchored(anchor: &Path, field: &Path) -> PathBuf {
    if field.is_absolute() {
        return field.to_path_buf();
    }
    let mut out = PathBuf::new();
    if anchor.is_absolute() {
        out.push(std::path::Component::RootDir.as_os_str());
    }
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    for component in anchor.join(field).components() {
        match component {
            std::path::Component::CurDir | std::path::Component::RootDir => {}
            std::path::Component::ParentDir => {
                parts.pop();
            }
            std::path::Component::Prefix(prefix) => parts.push(prefix.as_os_str().to_owned()),
            std::path::Component::Normal(segment) => parts.push(segment.to_owned()),
        }
    }
    for part in parts {
        out.push(part);
    }
    out
}

/// Resolve a `secret:…` reference relative to the runtime file's directory,
/// the same provider pair Relay allows (environment and runtime-rooted files).
pub fn resolve_secret(runtime_path: &Path, reference: &str) -> Result<Vec<u8>, RenderProblem> {
    use registry_platform_config::{SecretProvider, SecretResolver};
    let root = runtime_anchor(runtime_path);
    let resolver =
        SecretResolver::new([SecretProvider::Environment, SecretProvider::File], root)
            .map_err(|err| RenderProblem::new(ProblemKind::RuntimeInvalid, format!("{err}")))?;
    let secret = resolver
        .resolve(reference)
        .map_err(|err| RenderProblem::new(ProblemKind::RuntimeInvalid, format!("{err}")))?;
    Ok(secret.expose_secret().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn runtime_yaml(body: &str) -> RenderRuntime {
        let text =
            format!("apiVersion: render.registrystack.org/v1alpha1\nkind: RenderRuntime\n{body}");
        serde_norway::from_str(&text).expect("runtime parses")
    }

    #[test]
    fn bind_defaults_to_loopback() {
        let runtime = runtime_yaml(
            "bundle:\n  path: /b\nauth:\n  apiKeyRef: secret:file/k\naudit:\n  directory: /a\n  integrityKeyRef: secret:file/k\n",
        );
        assert_eq!(runtime.server.bind, "127.0.0.1:8080");
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

    /// `load` on a runtime file written under a temporary directory, so the
    /// checks that only `load` performs are exercised.
    fn load_yaml(body: &str) -> Result<RenderRuntime, RenderProblem> {
        let home = tempfile::tempdir().expect("deployment home");
        let file = home.path().join("runtime.yaml");
        std::fs::write(
            &file,
            format!(
                "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderRuntime\nbundle:\n  path: /b\nauth:\n  apiKeyRef: secret:file/api.key\naudit:\n  directory: /a\n  integrityKeyRef: secret:file/audit.key\n{body}"
            ),
        )
        .expect("runtime file");
        load(&file).map(|(runtime, _)| runtime)
    }

    #[test]
    fn shutdown_grace_outside_the_supported_range_is_refused() {
        // A zero grace drops renders in flight on SIGTERM, and a grace past
        // the hour overflows the bounded wait the shutdown path computes.
        for grace in ["0", "3601", "10000000000000000000"] {
            let err = load_yaml(&format!("server:\n  shutdownGraceSeconds: {grace}\n"))
                .expect_err("out-of-range grace must be refused");
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
        for grace in [1, 3600] {
            let runtime = load_yaml(&format!("server:\n  shutdownGraceSeconds: {grace}\n"))
                .expect("grace at the range end loads");
            assert_eq!(runtime.server.shutdown_grace_seconds, grace);
        }
    }

    #[test]
    fn relative_bundle_and_audit_paths_anchor_to_the_runtime_file() {
        let home = tempfile::tempdir().expect("deployment home");
        let deploy = home.path().join("deploy");
        std::fs::create_dir_all(&deploy).expect("deploy directory");
        let file = deploy.join("runtime.yaml");
        std::fs::write(
            &file,
            "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderRuntime\nbundle:\n  path: ../bundle\nauth:\n  apiKeyRef: secret:file/api.key\naudit:\n  directory: ../audit\n  integrityKeyRef: secret:file/audit.key\n",
        )
        .expect("runtime file");
        let (runtime, _) = load(&file).expect("runtime loads");
        let home = std::fs::canonicalize(home.path()).expect("canonical home");
        assert_eq!(runtime.bundle.path, home.join("bundle"));
        assert_eq!(runtime.audit.directory, home.join("audit"));
    }

    #[test]
    fn absolute_bundle_and_audit_paths_are_kept_verbatim() {
        let home = tempfile::tempdir().expect("deployment home");
        let file = home.path().join("runtime.yaml");
        std::fs::write(
            &file,
            "apiVersion: render.registrystack.org/v1alpha1\nkind: RenderRuntime\nbundle:\n  path: /srv/render/bundle\nauth:\n  apiKeyRef: secret:file/api.key\naudit:\n  directory: /var/lib/render/audit\n  integrityKeyRef: secret:file/audit.key\n",
        )
        .expect("runtime file");
        let (runtime, _) = load(&file).expect("runtime loads");
        assert_eq!(runtime.bundle.path, PathBuf::from("/srv/render/bundle"));
        assert_eq!(
            runtime.audit.directory,
            PathBuf::from("/var/lib/render/audit")
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
        }
    }
}
