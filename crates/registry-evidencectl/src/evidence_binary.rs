//! Resolution of the Evidence runtime binary delegated work runs through.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, bail, Context as _, Result};

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

/// Refuse an `evidence` binary that is not the one this build delegates to.
///
/// Adopter tooling makes no semantic decision of its own: it asks `evidence`
/// and reports the answer. A foreign binary, or a build of another version,
/// therefore produces a result that reads exactly like a real one, and the
/// mismatch surfaces long after the run that was trusted. Asking the binary to
/// identify itself is the one check that cannot be delegated, so it happens
/// before any work is handed over.
pub(crate) fn ensure_matching_version(evidence_bin: &Path) -> Result<()> {
    let expected = registry_platform_buildinfo::DISPLAY_VERSION;
    let output = Command::new(evidence_bin)
        .arg("--version")
        .output()
        .with_context(|| {
            format!(
                "failed to ask {} for its version, which evidencectl {expected} must match before delegating any work",
                evidence_bin.display()
            )
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let reported = if output.status.success() {
        reported_version(&stdout)
    } else {
        None
    };
    let Some(reported) = reported else {
        bail!(
            "{} did not report an Evidence runtime version; evidencectl {expected} delegates every fixture decision to the matching evidence binary, so pass --evidence-bin pointing at it, set EVIDENCE_BIN, or put it on PATH",
            evidence_bin.display()
        );
    };
    if reported != expected {
        bail!(
            "evidence at {} reports version {reported}, and this evidencectl is {expected}; the two must match, so pass --evidence-bin pointing at evidence {expected}, set EVIDENCE_BIN to it, or put it on PATH",
            evidence_bin.display()
        );
    }
    Ok(())
}

/// Read the version out of `evidence <version>`, the single line the runtime
/// prints for `--version`. Anything else is not that runtime identifying
/// itself, and is reported as such rather than parsed into a guess.
fn reported_version(stdout: &str) -> Option<&str> {
    let line = stdout.lines().find(|line| !line.trim().is_empty())?;
    let version = line.trim().strip_prefix("evidence ")?.trim();
    (!version.is_empty()).then_some(version)
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

#[cfg(test)]
mod tests {
    use super::reported_version;

    #[test]
    fn the_runtimes_own_version_line_is_read() {
        assert_eq!(reported_version("evidence 1.2.3\n"), Some("1.2.3"));
        assert_eq!(reported_version("evidence 1.2.3-dev\n"), Some("1.2.3-dev"));
    }

    #[test]
    fn a_line_that_is_not_the_runtime_identifying_itself_reads_as_nothing() {
        assert_eq!(reported_version(""), None);
        assert_eq!(reported_version("\n\n"), None);
        assert_eq!(reported_version("evidence\n"), None);
        assert_eq!(reported_version("evidence \n"), None);
        assert_eq!(reported_version("evidencectl 1.2.3\n"), None);
        assert_eq!(reported_version("some other tool 1.2.3\n"), None);
    }

    #[test]
    fn only_the_first_printed_line_identifies_the_binary() {
        assert_eq!(
            reported_version("evidence 1.2.3\nevidence 9.9.9\n"),
            Some("1.2.3")
        );
        assert_eq!(reported_version("banner\nevidence 1.2.3\n"), None);
    }
}
