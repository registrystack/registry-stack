//! Resolution of the Evidence runtime binary delegated work runs through, and
//! the bounds every delegated run is held to.

use std::{
    env,
    fs::{self, File},
    io::{Read as _, Seek as _},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};

/// How long a delegated `evidence` run may take before evidencectl stops it.
///
/// Compilation and fixture evaluation are local, bounded work against a bundle
/// the runtime already holds, so ten minutes is far past what any of it needs.
/// The deadline exists so a child that never exits cannot hold a build open.
pub(crate) const DELEGATED_RUN_DEADLINE: Duration = Duration::from_secs(600);

/// How long the `--version` handshake may take.
///
/// The runtime prints one line and exits, so thirty seconds bounds a binary
/// that hangs before evidencectl has handed it any work.
pub(crate) const VERSION_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

/// The most `evidence --version` may print before evidencectl stops reading.
///
/// One version line is a few dozen bytes. Anything near this is not a runtime
/// identifying itself.
const MAX_VERSION_OUTPUT_BYTES: u64 = 64 * 1024;

/// How often a delegated run is checked while it is still running.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug)]
pub(crate) struct DelegatedRunBoundError {
    message: String,
}

impl std::fmt::Display for DelegatedRunBoundError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for DelegatedRunBoundError {}

/// Resolve an explicit binary, `EVIDENCE_BIN`, or the first executable on
/// `PATH`, in that order.
pub(crate) fn resolve(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if !path.is_file() {
            return Err(operational_error(format!(
                "evidence binary not found at {}",
                path.display()
            )));
        }
        return Ok(path.to_path_buf());
    }
    if let Ok(env_path) = env::var("EVIDENCE_BIN") {
        let path = PathBuf::from(&env_path);
        if !path.is_file() {
            return Err(operational_error(format!(
                "evidence binary not found at {} (from EVIDENCE_BIN)",
                path.display()
            )));
        }
        return Ok(path);
    }
    find_on_path("evidence").ok_or_else(|| {
        operational_error(
            "evidence binary not found: pass --evidence-bin, set EVIDENCE_BIN, or add `evidence` to PATH",
        )
    })
}

fn operational_error(message: impl Into<String>) -> anyhow::Error {
    std::io::Error::new(std::io::ErrorKind::NotFound, message.into()).into()
}

/// Resolve the Evidence runtime binary and refuse one that is not this
/// build's, in the one order every delegating command needs.
///
/// Resolution and the version handshake belong together: a command that
/// resolves without asking would hand work to whatever `evidence` happened to
/// be reachable, and the answer it printed would read exactly like one from
/// the matching runtime.
pub(crate) fn resolve_matching(explicit: Option<&Path>) -> Result<PathBuf> {
    let evidence_bin = resolve(explicit)?;
    ensure_matching_version(&evidence_bin)?;
    Ok(evidence_bin)
}

pub(crate) fn resolve_matching_within(
    explicit: Option<&Path>,
    deadline: Duration,
) -> Result<PathBuf> {
    let evidence_bin = resolve(explicit)?;
    ensure_matching_version_within(&evidence_bin, deadline)?;
    Ok(evidence_bin)
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
    ensure_matching_version_within(evidence_bin, VERSION_HANDSHAKE_DEADLINE)
}

fn ensure_matching_version_within(evidence_bin: &Path, deadline: Duration) -> Result<()> {
    let expected = registry_platform_buildinfo::DISPLAY_VERSION;
    let (status, printed) = ask_for_version(evidence_bin, deadline).with_context(|| {
        format!(
            "failed to ask {} for its version, which evidencectl {expected} must match before delegating any work",
            evidence_bin.display()
        )
    })?;

    let stdout = String::from_utf8_lossy(&printed).into_owned();
    let reported = if status.success() {
        reported_version(&stdout)
    } else {
        None
    };
    let Some(reported) = reported else {
        return Err(operational_invalid_data(format!(
            "{} did not report an Evidence runtime version; evidencectl {expected} delegates every fixture decision to the matching evidence binary, so pass --evidence-bin pointing at it, set EVIDENCE_BIN, or put it on PATH",
            evidence_bin.display()
        )));
    };
    if reported != expected {
        return Err(operational_invalid_data(format!(
            "evidence at {} reports version {reported}, and this evidencectl is {expected}; the two must match, so pass --evidence-bin pointing at evidence {expected}, set EVIDENCE_BIN to it, or put it on PATH",
            evidence_bin.display()
        )));
    }
    Ok(())
}

fn operational_invalid_data(message: impl Into<String>) -> anyhow::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into()).into()
}

/// Ask the binary to identify itself, under the bounds every delegated run is
/// held to: a private capture the child writes into, a byte limit on what it
/// may print, and a deadline.
///
/// A binary that never answers is exactly the case this handshake exists to
/// catch, so waiting for one forever would defeat it.
fn ask_for_version(evidence_bin: &Path, deadline: Duration) -> Result<(ExitStatus, Vec<u8>)> {
    let what = format!("the version handshake with {}", evidence_bin.display());
    let mut capture =
        tempfile::tempfile().with_context(|| format!("creating a private capture for {what}"))?;
    let mut child = Command::new(evidence_bin)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::from(capture.try_clone()?))
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("starting {what}"))?;
    let status = wait_bounded(&mut child, &what, deadline, &|| Ok(()), &|| {
        capture_over_limit(&capture, MAX_VERSION_OUTPUT_BYTES)
    })?;
    let stdout = drain_capture(&mut capture, MAX_VERSION_OUTPUT_BYTES, &what)?;
    Ok((status, stdout))
}

/// Wait for a delegated `evidence` child under three bounds: the caller's
/// interruption, a byte limit the caller measures, and a deadline.
///
/// A child that outlives any of the three is stopped and reaped, so no
/// delegated run holds a command open on a binary that never finishes.
pub(crate) fn wait_bounded(
    child: &mut Child,
    what: &str,
    deadline: Duration,
    interrupted: &dyn Fn() -> Result<()>,
    over_limit: &dyn Fn() -> bool,
) -> Result<ExitStatus> {
    let started = Instant::now();
    loop {
        if let Err(error) = interrupted() {
            terminate_child(child);
            return Err(error);
        }
        if over_limit() {
            terminate_child(child);
            return Err(DelegatedRunBoundError {
                message: format!("{what} output exceeded its byte limit"),
            }
            .into());
        }
        if started.elapsed() > deadline {
            terminate_child(child);
            return Err(DelegatedRunBoundError {
                message: format!("{what} did not finish within its {deadline:?} deadline"),
            }
            .into());
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => {
                terminate_child(child);
                return Err(error).context(format!("waiting for {what}"));
            }
        }
    }
}

/// Whether a delegated child has already written more than it is allowed to.
pub(crate) fn capture_over_limit(file: &File, limit: u64) -> bool {
    file.metadata().is_ok_and(|metadata| metadata.len() > limit)
}

/// Read a finished child's capture back, refusing one that ran past its limit.
pub(crate) fn drain_capture(file: &mut File, limit: u64, what: &str) -> Result<Vec<u8>> {
    let mut captured = Vec::new();
    file.rewind()?;
    file.take(limit + 1).read_to_end(&mut captured)?;
    if captured.len() as u64 > limit {
        return Err(DelegatedRunBoundError {
            message: format!("{what} output exceeded its byte limit"),
        }
        .into());
    }
    Ok(captured)
}

/// Stop a delegated child and reap it.
///
/// Both calls report failure only when the child is already gone, which is the
/// state this function exists to reach.
pub(crate) fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
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

/// Run a freshly written executable stub, waiting only for Linux ETXTBSY.
/// A concurrent test's fork can inherit the writer descriptor until its own
/// exec closes it. Deployed binaries are not being written, so this bounded
/// retry belongs exclusively to tests, never runtime delegation.
#[cfg(test)]
pub(crate) fn retry_busy_stub<T>(run: impl FnMut() -> Result<T>) -> Result<T> {
    let deadline = Instant::now() + Duration::from_secs(5);
    retry_busy_stub_while(run, || {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
        true
    })
}

#[cfg(test)]
fn retry_busy_stub_while<T>(
    mut run: impl FnMut() -> Result<T>,
    mut wait_and_retry: impl FnMut() -> bool,
) -> Result<T> {
    loop {
        match run() {
            Err(error)
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::ExecutableFileBusy)
                }) && wait_and_retry() => {}
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::OpenOptions, io::Write as _, os::unix::fs::OpenOptionsExt as _, path::Path};

    use super::{
        ensure_matching_version_within, reported_version, retry_busy_stub, retry_busy_stub_while,
        Duration,
    };

    fn write_stub(path: &Path, script: &str) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(path)
            .expect("stub");
        file.write_all(script.as_bytes()).expect("write stub");
    }

    /// A binary that never answers is exactly what the handshake exists to
    /// catch, so waiting for one forever would defeat it.
    #[test]
    fn a_binary_that_never_answers_the_handshake_is_refused_at_the_deadline() {
        let root = tempfile::tempdir().expect("tempdir");
        let evidence = root.path().join("evidence-stub");
        write_stub(&evidence, "#!/bin/sh\nsleep 60\n");

        let error = retry_busy_stub(|| {
            ensure_matching_version_within(&evidence, Duration::from_millis(200))
        })
        .expect_err("a binary that never answers must be refused");

        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains("did not finish within its 200ms deadline"),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains("must match before delegating any work"),
            "the refusal must say why the handshake matters: {diagnostic}"
        );
    }

    /// A binary that answers without end is not a runtime printing one line.
    #[test]
    fn a_binary_that_floods_the_handshake_is_refused_at_its_byte_limit() {
        let root = tempfile::tempdir().expect("tempdir");
        let evidence = root.path().join("evidence-stub");
        write_stub(
            &evidence,
            "#!/bin/sh\nyes 'evidence 0.0.0' | head -c 1048576\n",
        );

        let error =
            retry_busy_stub(|| ensure_matching_version_within(&evidence, Duration::from_secs(30)))
                .expect_err("a flooding binary must be refused");

        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains("output exceeded its byte limit"),
            "{diagnostic}"
        );
    }

    #[test]
    fn a_binary_that_answers_at_once_completes_the_handshake() {
        let root = tempfile::tempdir().expect("tempdir");
        let evidence = root.path().join("evidence-stub");
        write_stub(
            &evidence,
            &format!(
                "#!/bin/sh\necho 'evidence {}'\n",
                registry_platform_buildinfo::DISPLAY_VERSION
            ),
        );

        retry_busy_stub(|| ensure_matching_version_within(&evidence, Duration::from_secs(30)))
            .expect("the matching runtime is accepted");
    }

    #[test]
    fn freshly_written_stub_retries_a_busy_error_in_its_context_chain() {
        let mut attempts = 0;
        let result = retry_busy_stub_while(
            || {
                attempts += 1;
                if attempts == 1 {
                    Err(anyhow::Error::new(std::io::Error::from(
                        std::io::ErrorKind::ExecutableFileBusy,
                    ))
                    .context("starting test stub"))
                } else {
                    Ok("completed")
                }
            },
            || true,
        );
        assert_eq!(result.unwrap(), "completed");
        assert_eq!(attempts, 2);
    }

    #[test]
    fn freshly_written_stub_preserves_an_unrelated_failure_without_waiting() {
        let error = retry_busy_stub_while::<()>(
            || {
                Err(
                    anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                        .context("starting test stub"),
                )
            },
            || panic!("only an executable-busy failure may wait"),
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(error.to_string(), "starting test stub");
    }

    #[test]
    fn freshly_written_stub_returns_the_busy_failure_when_the_wait_expires() {
        let mut attempts = 0;
        let mut waits = 0;
        let error = retry_busy_stub_while::<()>(
            || {
                attempts += 1;
                Err(std::io::Error::from(std::io::ErrorKind::ExecutableFileBusy).into())
            },
            || {
                waits += 1;
                waits < 3
            },
        )
        .unwrap_err();
        assert_eq!(attempts, 3);
        assert_eq!(waits, 3);
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::ExecutableFileBusy
        );
    }

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
