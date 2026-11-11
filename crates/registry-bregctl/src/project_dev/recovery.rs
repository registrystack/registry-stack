// SPDX-License-Identifier: Apache-2.0
//! Wait for the guards that own a lost worker's child processes.

use anyhow::{bail, ensure, Context, Result};
use rustix::fs::{flock, FlockOperation};
use std::{
    fs::{self, File},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const GUARD_WAIT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(100);

/// One row of the process table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Row {
    pub pid: u32,
    pub pgid: u32,
    pub started: String,
}

/// Every process with its group and start time. `ps` is the one portable
/// source of start times on Linux and macOS.
pub(super) fn process_table() -> Result<Vec<Row>> {
    let output = ps_command()
        .output()
        .context("cannot run ps to read process start times")?;
    ensure!(
        output.status.success(),
        "ps could not list processes with their start times"
    );
    Ok(parse_table(&String::from_utf8_lossy(&output.stdout)))
}

/// The `ps` call behind [`process_table`].
fn ps_command() -> Command {
    let mut command = Command::new("ps");
    command
        .args(["-A", "-o", "pid=,pgid=,lstart="])
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn parse_table(text: &str) -> Vec<Row> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse().ok()?;
            let pgid = fields.next()?.parse().ok()?;
            // The start time is several words; spacing differs between
            // platforms, so it is kept with single spaces.
            let started = fields.collect::<Vec<_>>().join(" ");
            (!started.is_empty()).then_some(Row { pid, pgid, started })
        })
        .collect()
}

/// The start time of `pid`, or `None` when it cannot be read.
#[cfg(test)]
pub(super) fn started_at(pid: u32) -> Option<String> {
    process_table()
        .ok()?
        .into_iter()
        .find(|row| row.pid == pid)
        .map(|row| row.started)
}

/// The worker creates each lock before launching a guard. Once the worker
/// has exited, a late guard cannot start a workload because its control pipe
/// is closed. A guard already running a workload holds its lock through reap.
pub(super) fn wait_for_guards(root: &Path) -> Result<Vec<u32>> {
    wait_for_guards_until(root, Instant::now() + GUARD_WAIT)?;
    super::guard::runtime_groups(root)
}

fn wait_for_guards_until(root: &Path, deadline: Instant) -> Result<()> {
    let directory = root.join(super::guard::DIRECTORY);
    let entries = fs::read_dir(directory).context("cannot read the run's process guards")?;
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("lock") {
            continue;
        }
        let lock = File::open(&path).context("cannot open a run process guard lock")?;
        loop {
            match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(rustix::io::Errno::WOULDBLOCK) if Instant::now() < deadline => {
                    thread::sleep(POLL);
                }
                Err(rustix::io::Errno::WOULDBLOCK) => {
                    bail!("a run process guard is still stopping its workload");
                }
                Err(error) => return Err(error).context("cannot check a run process guard lock"),
            }
        }
    }
    let incomplete = super::guard::incomplete_launches(root)?;
    ensure!(
        incomplete.is_empty(),
        "process guards did not confirm cleanup for {}",
        incomplete.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_times_are_read_in_one_locale_and_time_zone() {
        use std::ffi::OsStr;
        let command = ps_command();
        let envs: Vec<_> = command.get_envs().collect();
        for (name, value) in [("LC_ALL", "C"), ("TZ", "UTC")] {
            assert!(
                envs.contains(&(OsStr::new(name), Some(OsStr::new(value)))),
                "{name}: {envs:?}"
            );
        }
    }

    fn row(pid: u32, pgid: u32, started: &str) -> Row {
        Row {
            pid,
            pgid,
            started: started.to_owned(),
        }
    }

    #[test]
    fn the_process_table_parses_spaced_start_times() {
        let table = parse_table(
            "    1     1 Tue Nov  3 10:00:00 2026\n  4242  4242 Tue Nov 11 12:00:01 2026\nbad line\n",
        );
        assert_eq!(
            table,
            [
                row(1, 1, "Tue Nov 3 10:00:00 2026"),
                row(4242, 4242, "Tue Nov 11 12:00:01 2026"),
            ]
        );
    }

    #[test]
    fn a_held_guard_lock_prevents_recovery() {
        let root = tempfile::tempdir().unwrap();
        let guards = root.path().join("guards");
        std::fs::create_dir(&guards).unwrap();
        let path = guards.join("test.lock");
        let lock = std::fs::File::create(&path).unwrap();
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).unwrap();

        let error = wait_for_guards_until(root.path(), Instant::now()).unwrap_err();
        assert!(error.to_string().contains("process guard"), "{error:#}");
        drop(lock);
        wait_for_guards_until(root.path(), Instant::now()).unwrap();
    }

    #[test]
    fn a_released_guard_must_have_confirmed_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let guards = root.path().join("guards");
        std::fs::create_dir(&guards).unwrap();
        std::fs::File::create(guards.join("test.lock")).unwrap();
        let receipt = guards.join("test.state");
        std::fs::write(&receipt, "launching\n").unwrap();

        let error = wait_for_guards_until(root.path(), Instant::now()).unwrap_err();
        assert!(
            error.to_string().contains("did not confirm cleanup"),
            "{error:#}"
        );
        std::fs::write(receipt, "complete\n").unwrap();
        wait_for_guards_until(root.path(), Instant::now()).unwrap();
    }

    #[test]
    fn a_run_without_guard_metadata_cannot_be_recovered_automatically() {
        let root = tempfile::tempdir().unwrap();
        let error = wait_for_guards_until(root.path(), Instant::now()).unwrap_err();
        assert!(error.to_string().contains("process guards"), "{error:#}");
    }
}
