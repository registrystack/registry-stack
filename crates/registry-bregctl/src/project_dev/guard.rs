// SPDX-License-Identifier: Apache-2.0
//! Own one development child process group beyond the worker's lifetime.

use anyhow::{ensure, Context, Result};
use rustix::{
    fs::{fcntl_getfl, fcntl_setfl, flock, FlockOperation, OFlags},
    process::{kill_process_group, waitid, Pid, Signal, WaitId, WaitIdOptions},
};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::{
        fd::AsFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{self, ChildStdin, ExitCode, ExitStatus, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use super::{private_directory, write_private, POLL};

pub(super) const DIRECTORY: &str = "guards";
const START_WAIT: Duration = Duration::from_secs(5);
const LAUNCHING: &[u8] = b"launching\n";
const COMPLETE: &[u8] = b"complete\n";
static NEXT_GUARD: AtomicU64 = AtomicU64::new(0);

#[derive(clap::Args, Debug)]
pub(crate) struct Args {
    #[arg(long)]
    lock: PathBuf,
    #[arg(long)]
    pid_file: PathBuf,
    #[arg(long)]
    state_file: PathBuf,
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<OsString>,
}

/// The hidden bregctl entry point used by a development worker.
pub(crate) fn run(args: Args) -> ExitCode {
    match run_inner(args) {
        Ok(status) => exit_code(status),
        Err(error) => {
            eprintln!("development process guard failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner(args: Args) -> Result<ExitStatus> {
    let (program, arguments) = args
        .command
        .split_first()
        .context("the process guard command is empty")?;
    let mut command = process::Command::new(program);
    command
        .args(arguments)
        .env_remove("RSTACK_DEV_DATABASE_URL")
        .env_remove("RSTACK_PROJECT_DEV_REQUEST")
        .process_group(0)
        .stdin(Stdio::null());
    let mut controller = io::stdin();
    supervise(
        &args.lock,
        &args.pid_file,
        &args.state_file,
        &mut controller,
        command,
    )
}

/// Take the lock and check the lifetime pipe before spawning. Recovery first
/// excludes the worker and then takes these same locks, so a delayed guard
/// cannot start a workload after its worker has died.
fn supervise(
    lock_path: &Path,
    pid_file: &Path,
    state_file: &Path,
    controller: &mut (impl Read + AsFd),
    mut command: process::Command,
) -> Result<ExitStatus> {
    let lock = open_lock(lock_path)?;
    flock(&lock, FlockOperation::LockExclusive).context("cannot lock the process guard")?;
    set_nonblocking(&*controller)?;
    if !controller_alive(controller)? {
        return Ok(success_status());
    }

    // This receipt precedes spawn. If the guard dies unexpectedly after this
    // point, recovery sees an incomplete launch after the lock is released and
    // refuses to claim cleanup succeeded.
    write_private(state_file, LAUNCHING)?;
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            write_private(state_file, COMPLETE)?;
            return Err(error).context("cannot start guarded command");
        }
    };
    let mut workload = Workload::new(child);
    let operation = (|| -> Result<()> {
        write_private(pid_file, workload.child().id().to_string().as_bytes())?;
        loop {
            if direct_child_exited(workload.child())? || !controller_alive(controller)? {
                return Ok(());
            }
            thread::sleep(POLL);
        }
    })();
    let status = workload.stop()?;
    write_private(state_file, COMPLETE)?;
    operation?;
    Ok(status)
}

fn complete_state(path: &Path) -> Result<()> {
    ensure!(
        fs::read(path)? == COMPLETE,
        "process guard did not record completed cleanup"
    );
    Ok(())
}

fn incomplete_state(path: &Path) -> Result<bool> {
    let state = fs::read(path)?;
    ensure!(
        state == LAUNCHING || state == COMPLETE,
        "process guard has an invalid lifecycle receipt"
    );
    Ok(state != COMPLETE)
}

/// Released guard locks with these receipts cannot establish that the
/// workload group was reaped. Recovery must refuse cleanup for the run.
pub(super) fn incomplete_launches(root: &Path) -> Result<Vec<String>> {
    let directory = root.join(DIRECTORY);
    let mut launches = Vec::new();
    let mut pid_stems = Vec::new();
    for entry in fs::read_dir(&directory).with_context(|| {
        format!(
            "cannot read process guard directory {}",
            directory.display()
        )
    })? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".state") && incomplete_state(&entry.path())? {
            launches.push(name.trim_end_matches(".state").to_owned());
        } else if name.ends_with(".pid") {
            pid_stems.push(name.trim_end_matches(".pid").to_owned());
        }
    }
    for stem in pid_stems {
        if !directory.join(format!("{stem}.state")).is_file() {
            launches.push(stem);
        }
    }
    launches.sort();
    launches.dedup();
    Ok(launches)
}

/// Keep the lock's scope outside this owner, so every return path stops and
/// reaps a spawned workload before the lock is released.
struct Workload {
    child: Option<process::Child>,
}

impl Workload {
    fn new(child: process::Child) -> Self {
        Self { child: Some(child) }
    }

    fn child(&self) -> &process::Child {
        self.child.as_ref().expect("workload is live")
    }

    fn stop(&mut self) -> Result<ExitStatus> {
        let mut child = self.child.take().expect("workload is live");
        match stop_direct_child(&mut child) {
            Ok(status) => Ok(status),
            Err(error) => {
                self.child = Some(child);
                Err(error)
            }
        }
    }
}

impl Drop for Workload {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        // An error after spawn must not release the guard lock while the group
        // remains live. If the structured stop failed, retain the lock while
        // this final attempt kills the leader and waits for it.
        if stop_direct_child(&mut child).is_err() {
            let pid = direct_child_pid(&child).ok();
            if let Some(pid) = pid {
                let _ = kill_process_group(pid, Signal::KILL);
            }
            let _ = child.kill();
            // If signaling failed unexpectedly, waiting here retains the
            // guard lock instead of letting recovery overclaim cleanup.
            let _ = child.wait();
        }
    }
}

fn open_lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .with_context(|| format!("cannot open process guard lock {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "the process guard lock is not a file");
    ensure!(
        metadata.permissions().mode() & 0o777 == 0o600,
        "the process guard lock is not owner-only"
    );
    ensure!(
        metadata.uid() == rustix::process::getuid().as_raw(),
        "the process guard lock has another owner"
    );
    Ok(file)
}

fn set_nonblocking(fd: impl AsFd) -> Result<()> {
    let flags = fcntl_getfl(&fd)?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK)?;
    Ok(())
}

/// A lifetime pipe carries no protocol data. EOF alone means the worker no
/// longer owns the guarded process and the guard must stop it.
fn controller_alive(controller: &mut impl Read) -> Result<bool> {
    let mut byte = [0_u8; 1];
    loop {
        match controller.read(&mut byte) {
            Ok(0) => return Ok(false),
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("cannot read the process guard lifetime pipe"),
        }
    }
}

pub(super) fn direct_child_pid(child: &process::Child) -> Result<Pid> {
    Pid::from_raw(i32::try_from(child.id())?).context("invalid owned process ID")
}

pub(super) fn direct_child_exited(child: &process::Child) -> Result<bool> {
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    loop {
        match waitid(WaitId::Pid(direct_child_pid(child)?), options) {
            Ok(status) => return Ok(status.is_some()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn signal_group(child: &process::Child, signal: Signal) -> Result<()> {
    match kill_process_group(direct_child_pid(child)?, signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        // Darwin reports EPERM when an exited leader has no signalable group
        // members. The leader remains our unreaped child, so this is empty.
        Err(rustix::io::Errno::PERM)
            if cfg!(target_os = "macos") && direct_child_exited(child)? =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) fn stop_direct_child(child: &mut process::Child) -> Result<ExitStatus> {
    if !direct_child_exited(child)? {
        signal_group(child, Signal::TERM)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && !direct_child_exited(child)? {
            thread::sleep(POLL);
        }
    }
    // Keep the leader PID reserved until the final group signal, then reap it.
    signal_group(child, Signal::KILL)?;
    Ok(child.wait()?)
}

fn success_status() -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(0)
}

fn exit_code(status: ExitStatus) -> ExitCode {
    status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .map(ExitCode::from)
        .unwrap_or(ExitCode::FAILURE)
}

/// Builder for a command whose process group is owned by a guard. Output and
/// error streams belong to the guard and are inherited unchanged by the
/// workload, preserving the tool's JSON and log behavior.
pub(super) struct Command {
    command: process::Command,
    pid_file: PathBuf,
    state_file: PathBuf,
}

impl Command {
    pub(super) fn new(root: &Path, name: &str, binary: &Path) -> Result<Self> {
        let directory = root.join(DIRECTORY);
        match private_directory(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("cannot create process guard directory"),
        }
        ensure!(
            fs::metadata(&directory)?.permissions().mode() & 0o777 == 0o700,
            "the process guard directory is not owner-only"
        );

        let sequence = NEXT_GUARD.fetch_add(1, Ordering::Relaxed);
        let stem = format!("{sequence:016x}-{name}");
        let lock = directory.join(format!("{stem}.lock"));
        let lock_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock)
            .with_context(|| format!("cannot create process guard lock {}", lock.display()))?;
        lock_file.set_permissions(fs::Permissions::from_mode(0o600))?;
        let pid_file = directory.join(format!("{stem}.pid"));
        let state_file = directory.join(format!("{stem}.state"));
        let mut command = process::Command::new(std::env::current_exe()?);
        command
            .arg("project-dev-guard")
            .arg("--lock")
            .arg(lock)
            .arg("--pid-file")
            .arg(&pid_file)
            .arg("--state-file")
            .arg(&state_file)
            .arg("--")
            .arg(binary)
            .env_remove("RSTACK_DEV_DATABASE_URL")
            .env_remove("RSTACK_PROJECT_DEV_REQUEST")
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Ok(Self {
            command,
            pid_file,
            state_file,
        })
    }

    pub(super) fn arg(&mut self, argument: impl AsRef<OsStr>) -> &mut Self {
        self.command.arg(argument);
        self
    }

    pub(super) fn args<I, S>(&mut self, arguments: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.command.args(arguments);
        self
    }

    pub(super) fn stdout(&mut self, stream: impl Into<Stdio>) -> &mut Self {
        self.command.stdout(stream);
        self
    }

    pub(super) fn stderr(&mut self, stream: impl Into<Stdio>) -> &mut Self {
        self.command.stderr(stream);
        self
    }

    pub(super) fn spawn(&mut self) -> Result<Child> {
        let mut guard = self.command.spawn().context("cannot start process guard")?;
        let controller = guard
            .stdin
            .take()
            .context("process guard stdin was not piped")?;
        let started: Result<Pid> = (|| -> Result<Pid> {
            let deadline = Instant::now() + START_WAIT;
            loop {
                match fs::read_to_string(&self.pid_file) {
                    Ok(value) => {
                        let raw: i32 =
                            value.trim().parse().context("invalid guarded process ID")?;
                        let pid = Pid::from_raw(raw).context("invalid guarded process ID")?;
                        return Ok(pid);
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error).context("cannot read guarded process ID"),
                }
                if guard.try_wait()?.is_some() {
                    anyhow::bail!("process guard exited before starting its workload");
                }
                ensure!(
                    Instant::now() < deadline,
                    "process guard did not publish its workload ID"
                );
                thread::sleep(Duration::from_millis(10));
            }
        })();
        match started {
            Ok(pid) => Ok(Child {
                guard,
                controller: Some(controller),
                pid,
                state_file: self.state_file.clone(),
            }),
            Err(error) => {
                drop(controller);
                let _ = guard.wait();
                Err(error)
            }
        }
    }
}

/// The worker's handle for a guard and its actual workload process group.
pub(super) struct Child {
    guard: process::Child,
    controller: Option<ChildStdin>,
    pid: Pid,
    state_file: PathBuf,
}

impl Child {
    pub(super) fn id(&self) -> u32 {
        self.pid
            .as_raw_pid()
            .try_into()
            .expect("positive process ID")
    }

    pub(super) fn exited(&self) -> Result<bool> {
        direct_child_exited(&self.guard)
    }

    pub(super) fn stop(&mut self) -> Result<ExitStatus> {
        drop(self.controller.take());
        let status = self.guard.wait()?;
        complete_state(&self.state_file)?;
        Ok(status)
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.controller.is_none() {
            return;
        }
        if let Err(error) = self.stop() {
            eprintln!("development process guard cleanup failed: {error:#}");
        }
    }
}

/// The actual runtime groups a run started. Recovery uses this only for its
/// success report after every guard lock is free, never as a signaling source.
pub(super) fn runtime_groups(root: &Path) -> Result<Vec<u32>> {
    let directory = root.join(DIRECTORY);
    let mut groups = Vec::new();
    for entry in fs::read_dir(&directory).with_context(|| {
        format!(
            "cannot read process guard directory {}",
            directory.display()
        )
    })? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.contains("-runtime-") || !name.ends_with(".pid") {
            continue;
        }
        complete_state(&entry.path().with_extension("state"))?;
        let raw: u32 = fs::read_to_string(entry.path())?
            .trim()
            .parse()
            .context("invalid guarded runtime process ID")?;
        groups.push(raw);
    }
    groups.sort_unstable();
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::net::UnixStream, sync::mpsc};

    fn lock_file(root: &Path) -> PathBuf {
        let path = root.join("guard.lock");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        path
    }

    #[test]
    fn worker_death_before_pid_publication_spawns_no_workload() {
        let scratch = tempfile::tempdir().unwrap();
        let lock = lock_file(scratch.path());
        let pid_file = scratch.path().join("guard.pid");
        let state_file = scratch.path().join("guard.state");
        let marker = scratch.path().join("spawned");
        let (mut controller, worker) = UnixStream::pair().unwrap();
        drop(worker);
        let mut command = process::Command::new("/bin/sh");
        command.args(["-c", &format!("touch '{}'", marker.display())]);

        let status = supervise(&lock, &pid_file, &state_file, &mut controller, command).unwrap();
        assert!(status.success());
        assert!(!marker.exists());
        assert!(!pid_file.exists());
        assert!(!state_file.exists());
    }

    #[test]
    fn guard_owns_and_reaps_the_workload_process_group() {
        let scratch = tempfile::tempdir().unwrap();
        let lock = lock_file(scratch.path());
        let pid_file = scratch.path().join("guard.pid");
        let state_file = scratch.path().join("guard.state");
        let nested_file = scratch.path().join("nested.pid");
        let (mut controller, worker) = UnixStream::pair().unwrap();
        let (finished_tx, finished_rx) = mpsc::sync_channel(1);
        let mut command = process::Command::new("/bin/sh");
        command
            .args([
                "-c",
                &format!(
                    "sh -c 'trap \"\" TERM; exec sleep 60' & printf '%s' \"$!\" > '{}' ; wait",
                    nested_file.display()
                ),
            ])
            .process_group(0)
            .stdin(Stdio::null());
        let guard_lock = lock.clone();
        let guard_pid = pid_file.clone();
        let guard_state = state_file.clone();
        let guard_thread = thread::spawn(move || {
            let status = supervise(
                &guard_lock,
                &guard_pid,
                &guard_state,
                &mut controller,
                command,
            )
            .unwrap();
            finished_tx.send(status).unwrap();
        });

        let leader = wait_pid(&pid_file);
        let nested = wait_pid(&nested_file);
        assert_eq!(rustix::process::getpgid(Some(leader)).unwrap(), leader);
        assert_eq!(rustix::process::getpgid(Some(nested)).unwrap(), leader);
        let contender = open_lock(&lock).unwrap();
        assert_eq!(
            flock(&contender, FlockOperation::NonBlockingLockExclusive).unwrap_err(),
            rustix::io::Errno::WOULDBLOCK
        );

        drop(worker);
        finished_rx.recv_timeout(Duration::from_secs(4)).unwrap();
        guard_thread.join().unwrap();
        complete_state(&state_file).unwrap();
        flock(&contender, FlockOperation::NonBlockingLockExclusive).unwrap();
        assert_eq!(
            rustix::process::getpgid(Some(leader)).unwrap_err(),
            rustix::io::Errno::SRCH
        );
        assert_eq!(
            rustix::process::getpgid(Some(nested)).unwrap_err(),
            rustix::io::Errno::SRCH
        );
    }

    #[test]
    fn runtime_group_report_excludes_provisioning_tools() {
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join(DIRECTORY);
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("000-runtime-breg.pid"), "41").unwrap();
        fs::write(directory.join("000-runtime-breg.state"), COMPLETE).unwrap();
        fs::write(directory.join("001-tool-breg-check.pid"), "42").unwrap();
        fs::write(directory.join("001-tool-breg-check.state"), COMPLETE).unwrap();
        fs::write(directory.join("002-runtime-casework.pid"), "43").unwrap();
        fs::write(directory.join("002-runtime-casework.state"), COMPLETE).unwrap();
        assert_eq!(runtime_groups(scratch.path()).unwrap(), vec![41, 43]);
    }

    #[test]
    fn incomplete_launch_receipt_refuses_recovery() {
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join(DIRECTORY);
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("000-runtime-breg.state"), LAUNCHING).unwrap();
        fs::write(directory.join("001-tool-breg-check.state"), COMPLETE).unwrap();
        fs::write(directory.join("002-runtime-casework.pid"), "43").unwrap();
        assert_eq!(
            incomplete_launches(scratch.path()).unwrap(),
            vec!["000-runtime-breg", "002-runtime-casework"]
        );
    }

    fn wait_pid(path: &Path) -> Pid {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(value) = fs::read_to_string(path) {
                let raw = value.parse().unwrap();
                return Pid::from_raw(raw).unwrap();
            }
            assert!(Instant::now() < deadline, "PID was not published");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
