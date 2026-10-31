// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use std::{
    fs::OpenOptions,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

pub fn required_binary(name: &str) -> PathBuf {
    let path = required_absolute_path(name);
    assert!(path.is_file(), "{name} must name an existing executable");
    path
}

pub fn required_absolute_path(name: &str) -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required for the native proof")),
    );
    assert!(path.is_absolute(), "{name} must be an absolute path");
    path
}

pub fn private_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create private fixture directory");
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .expect("private fixture directory mode");
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .expect("create private fixture file");
    file.write_all(bytes).expect("write private fixture file");
}

pub fn json_document(path: &Path, value: &Value) {
    private_file(
        path,
        &serde_json::to_vec_pretty(value).expect("serialize fixture document"),
    );
}

pub fn copy_tree(source: &Path, destination: &Path) {
    assert!(source.is_dir(), "fixture source directory exists");
    std::fs::create_dir_all(destination).expect("create fixture copy root");
    for entry in std::fs::read_dir(source).expect("read fixture source directory") {
        let entry = entry.expect("read fixture source entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("fixture entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy maintained fixture file");
        }
    }
}

pub fn operator(binary: &Path, args: &[&std::ffi::OsStr], log: &Path) {
    let output = Command::new(binary)
        .arg("--format")
        .arg("json")
        .args(args)
        .output()
        .expect("native operator starts");
    let mut bytes = output.stdout;
    bytes.extend_from_slice(&output.stderr);
    private_file(log, &bytes);
    assert!(
        output.status.success(),
        "native operator failed; inspect {}",
        log.display()
    );
}

pub fn free_address() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve native service port")
        .local_addr()
        .expect("reserved native service address")
}

pub struct FixtureDirectory(Option<tempfile::TempDir>);

impl FixtureDirectory {
    pub const fn new(root: tempfile::TempDir) -> Self {
        Self(Some(root))
    }

    pub fn path(&self) -> &Path {
        self.0.as_ref().expect("fixture directory").path()
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(root) = self.0.take() {
                eprintln!(
                    "retained private native Casework evidence: {}",
                    root.keep().display()
                );
            }
        }
    }
}

pub struct ServiceProcess {
    child: Child,
    log: PathBuf,
}

impl ServiceProcess {
    pub async fn start(
        binary: &Path,
        args: &[&std::ffi::OsStr],
        log_path: PathBuf,
        ready_url: &str,
    ) -> Self {
        private_file(&log_path, b"");
        let log = OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect("open native service log");
        let child = Command::new(binary)
            .args(args)
            .stdout(Stdio::from(log.try_clone().expect("clone native log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("native service starts");
        let mut service = Self {
            child,
            log: log_path,
        };
        let http = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("native readiness client");
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            if let Some(status) = service.child.try_wait().expect("poll native service") {
                panic!(
                    "native service exited early ({status}); inspect {}",
                    service.log.display()
                );
            }
            if http
                .get(ready_url)
                .timeout(Duration::from_secs(2))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                return service;
            }
            assert!(
                Instant::now() < deadline,
                "native service did not become ready; inspect {}",
                service.log.display()
            );
            tokio::time::sleep(Duration::from_millis(75)).await;
        }
    }
}

impl Drop for ServiceProcess {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if let Err(kill_error) = self.child.kill() {
                    match self.child.try_wait() {
                        Ok(Some(_)) => return,
                        Ok(None) => {
                            eprintln!(
                                "native service termination failed ({kill_error}); inspect {}",
                                self.log.display()
                            );
                            return;
                        }
                        Err(status_error) => {
                            eprintln!(
                                "native service termination failed ({kill_error}) and status could not be checked ({status_error}); inspect {}",
                                self.log.display()
                            );
                            return;
                        }
                    }
                }
            }
            Err(error) => eprintln!(
                "native service status could not be checked before termination ({error}); inspect {}",
                self.log.display()
            ),
        }
        if let Err(error) = self.child.wait() {
            eprintln!(
                "native service wait failed after termination ({error}); inspect {}",
                self.log.display()
            );
        }
    }
}
