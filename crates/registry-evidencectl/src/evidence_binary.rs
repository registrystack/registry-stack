//! Resolution of the Evidence runtime binary delegated work runs through.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Result};

/// Resolve an explicit binary, `EVIDENCE_BIN`, or the first executable on
/// `PATH`, in that order.
pub(crate) fn resolve(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if !path.is_file() {
            bail!("evidence binary not found at {}", path.display());
        }
        return Ok(path.to_path_buf());
    }
    if let Ok(env_path) = env::var("EVIDENCE_BIN") {
        let path = PathBuf::from(&env_path);
        if !path.is_file() {
            bail!(
                "evidence binary not found at {} (from EVIDENCE_BIN)",
                path.display()
            );
        }
        return Ok(path);
    }
    find_on_path("evidence").ok_or_else(|| {
        anyhow!(
            "evidence binary not found: pass --evidence-bin, set EVIDENCE_BIN, or add `evidence` to PATH"
        )
    })
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    env::split_paths(&path_var).find_map(|dir| {
        let candidate = dir.join(name);
        is_candidate_executable(&candidate).then_some(candidate)
    })
}

fn is_candidate_executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}
