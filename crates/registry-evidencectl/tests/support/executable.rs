// SPDX-License-Identifier: Apache-2.0
//! Helpers for tests that run an executable written or copied moments before.
//!
//! On Linux a concurrent test's fork can hold the writer descriptor of a
//! freshly written file until its own exec closes it, and exec of that file
//! fails with ETXTBSY meanwhile. Only that error is waited for, for a bounded
//! time. Nothing else is retried. Each test binary includes this file with
//! `#[path = "support/executable.rs"] mod executable;` and uses a subset.
#![allow(dead_code)]

use std::{
    io,
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

const BUSY_BOUND: Duration = Duration::from_secs(5);

/// Run `command`, waiting out ETXTBSY for a binary written moments ago.
pub fn output_waiting_for_busy_binary(command: &mut Command) -> io::Result<Output> {
    let deadline = Instant::now() + BUSY_BOUND;
    retry_while_busy(|| command.output(), || Instant::now() < deadline)
}

/// Return only once the stub at `path` can be exec'd. A stub that another
/// process is about to exec (for example `evidencectl` resolving it) cannot
/// be retried by the test, so the test proves it runnable first; once one exec
/// has succeeded no later exec of the file can be refused. The stub is run
/// with `--version`, so it must answer that without side effects or delay.
pub fn wait_until_executable(path: &Path) {
    wait_until_executable_with(path, "--version");
}

/// As [`wait_until_executable`], probing with `argument` for a stub whose
/// `--version` answer has side effects or delay.
pub fn wait_until_executable_with(path: &Path, argument: &str) {
    let deadline = Instant::now() + BUSY_BOUND;
    retry_while_busy(
        || {
            Command::new(path)
                .arg(argument)
                .stdin(Stdio::null())
                .output()
        },
        || Instant::now() < deadline,
    )
    .unwrap_or_else(|error| panic!("the stub {} could not be run: {error}", path.display()));
}

pub fn retry_while_busy<T>(
    mut run: impl FnMut() -> io::Result<T>,
    mut keep_waiting: impl FnMut() -> bool,
) -> io::Result<T> {
    loop {
        match run() {
            Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy && keep_waiting() => {
                std::thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
}
