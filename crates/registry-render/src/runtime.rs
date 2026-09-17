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
    /// Loopback or private address; TLS is the proxy's job, not Render's.
    pub bind: String,
    /// Grace period for in-flight renders at shutdown.
    #[serde(default = "default_shutdown_grace_seconds")]
    pub shutdown_grace_seconds: u64,
}

fn default_shutdown_grace_seconds() -> u64 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BundleRuntime {
    /// Path to a sealed bundle directory.
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
    /// Directory for the sealed, hash-chained JSONL ledger.
    pub directory: PathBuf,
    /// `secret:file/…` reference to the chain integrity key (>= 32 bytes).
    pub integrity_key_ref: String,
    /// Sealed segment size before rotation.
    #[serde(default = "default_max_segment_bytes")]
    pub max_segment_bytes: u64,
}

pub fn default_max_segment_bytes() -> u64 {
    64 * 1024 * 1024
}

/// Load and validate a runtime file, expanding bounded `${VAR}` references.
/// Returns the runtime and its canonical sha256 config id.
pub fn load(path: &Path) -> Result<(RenderRuntime, String), RenderProblem> {
    let raw = std::fs::read_to_string(path).map_err(|err| {
        RenderProblem::new(
            ProblemKind::RuntimeInvalid,
            format!("cannot read runtime {}: {err}", path.display()),
        )
    })?;
    let expanded = registry_platform_config::expand_config_env_vars(&raw)
        .map_err(|err| RenderProblem::new(ProblemKind::RuntimeInvalid, format!("{err}")))?;
    let runtime: RenderRuntime = serde_norway::from_str(&expanded).map_err(|err| {
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
    let id = crate::hash::sha256_hex(expanded.as_bytes());
    Ok((runtime, id))
}

/// Resolve a `secret:…` reference relative to the runtime file's directory,
/// the same provider pair Relay allows (environment and runtime-rooted files).
pub fn resolve_secret(runtime_path: &Path, reference: &str) -> Result<Vec<u8>, RenderProblem> {
    use registry_platform_config::{SecretProvider, SecretResolver};
    let root = runtime_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));
    let root = std::fs::canonicalize(&root).unwrap_or(root);
    let resolver =
        SecretResolver::new([SecretProvider::Environment, SecretProvider::File], root)
            .map_err(|err| RenderProblem::new(ProblemKind::RuntimeInvalid, format!("{err}")))?;
    let secret = resolver
        .resolve(reference)
        .map_err(|err| RenderProblem::new(ProblemKind::RuntimeInvalid, format!("{err}")))?;
    Ok(secret.expose_secret().to_vec())
}
