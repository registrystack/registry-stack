// SPDX-License-Identifier: Apache-2.0
//! Releasing the processes of a run whose supervisor is lost.
//!
//! A recorded process group is signalled only while it still belongs to the
//! run: the leader's start time must equal the one recorded when the run
//! started. Process IDs are reused, so a recorded ID alone proves nothing.

use anyhow::{bail, ensure, Context, Result};
use rustix::process::{kill_process_group, Pid, Signal};
use serde_json::Value;
use std::{
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const TERM_GRACE: Duration = Duration::from_secs(5);
const KILL_GRACE: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(100);

/// One row of the process table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Row {
    pub pid: u32,
    pub pgid: u32,
    pub started: String,
}

/// What a recorded process group is now.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Group {
    /// No process of the group remains.
    Gone,
    /// The group is the run's own.
    Ours,
    /// The recorded ID belongs to a different process now.
    Reused,
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

/// Decide whether the recorded group `pgid` is still the run's. A group ID
/// stays reserved while any member lives, so a group whose leader has gone
/// but whose members remain is the original group.
pub(super) fn classify(table: &[Row], pgid: u32, recorded_start: Option<&str>) -> Result<Group> {
    match table.iter().find(|row| row.pid == pgid) {
        Some(leader) => {
            let recorded = recorded_start.with_context(|| {
                format!("process group {pgid} cannot be verified: its start time was not recorded")
            })?;
            Ok(if leader.started == recorded {
                Group::Ours
            } else {
                Group::Reused
            })
        }
        None if table.iter().any(|row| row.pgid == pgid) => Ok(Group::Ours),
        None => Ok(Group::Gone),
    }
}

fn signal(pgid: u32, signal: Signal) -> Result<()> {
    let pid = i32::try_from(pgid)
        .ok()
        .and_then(Pid::from_raw)
        .context("invalid process group ID")?;
    match kill_process_group(pid, signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        // Darwin reports EPERM for a group whose only members are zombies.
        Err(rustix::io::Errno::PERM) if cfg!(target_os = "macos") => Ok(()),
        Err(error) => Err(error).with_context(|| format!("cannot signal process group {pgid}")),
    }
}

fn wait_until_gone(groups: &[u32], grace: Duration) -> Result<Vec<u32>> {
    let deadline = Instant::now() + grace;
    loop {
        let table = process_table()?;
        let alive: Vec<u32> = groups
            .iter()
            .copied()
            .filter(|group| table.iter().any(|row| row.pgid == *group))
            .collect();
        if alive.is_empty() || Instant::now() >= deadline {
            return Ok(alive);
        }
        thread::sleep(POLL);
    }
}

/// Stop each group: TERM, then KILL for any that survive the grace period.
pub(super) fn stop_groups(groups: &[u32]) -> Result<()> {
    if groups.is_empty() {
        return Ok(());
    }
    for group in groups {
        signal(*group, Signal::TERM)?;
    }
    let survivors = wait_until_gone(groups, TERM_GRACE)?;
    for group in &survivors {
        signal(*group, Signal::KILL)?;
    }
    let remaining = wait_until_gone(&survivors, KILL_GRACE)?;
    if !remaining.is_empty() {
        bail!(
            "process group {} survived SIGKILL",
            remaining
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

/// The recorded processes of a run, sorted into those to stop and those whose
/// recorded ID now belongs to something else.
pub(super) struct Plan {
    pub ours: Vec<u32>,
    pub reused: Vec<u32>,
}

/// Classify every recorded process group before anything is signalled, so one
/// unverifiable entry stops the recovery with nothing touched.
pub(super) fn plan(recorded: &Value, table: &[Row]) -> Result<Plan> {
    let mut plan = Plan {
        ours: Vec::new(),
        reused: Vec::new(),
    };
    for entry in recorded.as_array().into_iter().flatten() {
        let pgid = entry["pgid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .context("a recorded process has no valid group ID")?;
        match classify(table, pgid, entry["started"].as_str())? {
            Group::Ours => plan.ours.push(pgid),
            Group::Reused => plan.reused.push(pgid),
            Group::Gone => {}
        }
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::process::CommandExt;

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
    fn a_group_is_ours_only_when_its_leader_started_when_recorded() {
        let table = [row(7, 7, "Tue Nov 11 12:00:00 2026")];
        assert_eq!(
            classify(&table, 7, Some("Tue Nov 11 12:00:00 2026")).unwrap(),
            Group::Ours
        );
        assert_eq!(
            classify(&table, 7, Some("Mon Nov 10 08:00:00 2026")).unwrap(),
            Group::Reused,
            "a reused process ID has a different start time"
        );
        let unverified = classify(&table, 7, None).unwrap_err().to_string();
        assert!(
            unverified.contains("start time was not recorded"),
            "{unverified}"
        );
    }

    #[test]
    fn a_group_without_a_leader_is_ours_while_members_remain() {
        let members = [row(8, 7, "Tue Nov 11 12:00:00 2026")];
        assert_eq!(classify(&members, 7, None).unwrap(), Group::Ours);
        assert_eq!(classify(&[], 7, None).unwrap(), Group::Gone);
    }

    #[test]
    fn nothing_is_signalled_when_one_recorded_process_cannot_be_verified() {
        let table = [row(7, 7, "A"), row(9, 9, "B")];
        let recorded = json!([
            {"product": "breg", "pid": 7, "pgid": 7, "started": "A"},
            {"product": "casework", "pid": 9, "pgid": 9, "started": null},
        ]);
        assert!(plan(&recorded, &table).is_err());
        let recorded = json!([
            {"product": "breg", "pid": 7, "pgid": 7, "started": "A"},
            {"product": "casework", "pid": 9, "pgid": 9, "started": "other"},
            {"product": "gone", "pid": 11, "pgid": 11, "started": "C"},
        ]);
        let plan = plan(&recorded, &table).unwrap();
        assert_eq!((plan.ours, plan.reused), (vec![7], vec![9]));
    }

    fn is_alive(pgid: u32) -> bool {
        process_table().unwrap().iter().any(|row| row.pgid == pgid)
    }

    /// A sleeping process in its own group, and a thread that reaps it once it
    /// ends, since an unreaped child stays in the process table.
    fn sleeper() -> (u32, thread::JoinHandle<()>) {
        let mut child = Command::new("sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        (
            pid,
            thread::spawn(move || {
                child.wait().unwrap();
            }),
        )
    }

    #[test]
    fn a_live_group_with_its_recorded_start_time_is_stopped() {
        let (pid, reaper) = sleeper();
        let started = started_at(pid).expect("a live process has a start time");
        let recorded = json!([{"product": "breg", "pid": pid, "pgid": pid, "started": started}]);
        let plan = plan(&recorded, &process_table().unwrap()).unwrap();
        assert_eq!(plan.ours, [pid]);
        stop_groups(&plan.ours).unwrap();
        reaper.join().unwrap();
        assert!(!is_alive(pid));
    }

    #[test]
    fn a_live_group_with_another_start_time_is_left_running() {
        let (pid, reaper) = sleeper();
        let recorded = json!([{"product": "breg", "pid": pid, "pgid": pid, "started": "Mon Jan 1 00:00:00 2001"}]);
        let plan = plan(&recorded, &process_table().unwrap()).unwrap();
        assert!(plan.ours.is_empty());
        assert_eq!(plan.reused, [pid]);
        assert!(is_alive(pid), "the unrelated process must keep running");
        signal(pid, Signal::KILL).unwrap();
        reaper.join().unwrap();
    }
}
