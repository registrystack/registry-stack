// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use tempfile::TempDir;

const TEST_VERSION: &str = "v9.8.7";

#[cfg(unix)]
#[test]
fn installer_refuses_to_run_without_a_pinned_release() {
    let fixture = InstallerFixture::new();
    let output = fixture.command_without_version().output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("RELAY_VERSION"), "stderr: {stderr}");
    assert!(!fixture.fake_curl_log().exists());
}

#[cfg(unix)]
#[test]
fn installer_rejects_noncanonical_release_tags_before_download() {
    for tag in [
        "9.8.7",
        "v9.8",
        "latest",
        "v09.8.7",
        "v9.8.7-rc1",
        "v9.8.7\nmalformed",
    ] {
        let fixture = InstallerFixture::new();
        let output = fixture.command_for_version(tag).output().unwrap();
        assert!(!output.status.success(), "tag {tag:?} must be refused");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("non-canonical"), "stderr: {stderr}");
        assert!(!fixture.fake_curl_log().exists());
    }
}

#[cfg(unix)]
#[test]
fn installer_help_describes_download_and_verification_contract() {
    let fixture = InstallerFixture::new();
    let mut command = fixture.command_without_version();
    command.arg("--help");
    let output = command.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "Registry Stack Relay runtime",
        "releases/latest/download/relay-install.sh | bash",
        "SHA256SUMS",
        "RELAY_ASSET_DIR",
        "release/VERIFY.md",
        "Linux amd64",
    ] {
        assert!(stdout.contains(expected), "help must mention {expected}");
    }
}

#[cfg(unix)]
#[test]
fn versioned_installer_selects_its_filename_release() {
    let fixture = InstallerFixture::new();
    let versioned = fixture
        .temp_path()
        .join(format!("relay-{TEST_VERSION}-install.sh"));
    fs::copy(installer_path(), &versioned).unwrap();
    let output = fixture.command_for(&versioned, false).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_relay_installed();
}

#[cfg(unix)]
#[test]
fn published_installer_supports_curl_pipe_and_rejects_mismatched_override() {
    let fixture = InstallerFixture::new();
    let rendered = fixture.rendered_installer();

    let output = fixture.command_from_stdin(&rendered).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_relay_installed();

    fs::remove_file(fixture.install_dir.join("relay")).unwrap();
    let mut mismatch = fixture.command_from_stdin(&rendered);
    mismatch.env("RELAY_VERSION", "v1.2.3");
    let output = mismatch.output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Refusing a release override"));
}

#[cfg(unix)]
#[test]
fn installer_checksum_verifies_and_installs_relay() {
    let fixture = InstallerFixture::new();
    let output = fixture.run();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_relay_installed();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Integrity check passed"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("Authenticity check not performed"),
        "stdout: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn verified_local_asset_mode_installs_without_network_downloads() {
    let fixture = InstallerFixture::new();
    let mut command = fixture.command();
    command.env("RELAY_ASSET_DIR", &fixture.release_dir);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_relay_installed();
    assert!(!fixture.fake_curl_log().exists());
}

#[cfg(unix)]
#[test]
fn unsupported_platform_fails_before_download_or_install() {
    let fixture = InstallerFixture::new();
    let mut command = fixture.command();
    command.env("FAKE_UNAME_M", "aarch64");
    let output = command.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Supported platform: Linux amd64"));
    assert!(!fixture.fake_curl_log().exists());
    assert!(!fixture.install_dir.exists());
}

#[cfg(unix)]
#[test]
fn checksum_refusals_preserve_an_existing_relay() {
    for mutation in [ChecksumMutation::Missing, ChecksumMutation::Mismatch] {
        let fixture = InstallerFixture::new();
        fixture.preinstall_relay();
        match mutation {
            ChecksumMutation::Missing => {
                fs::write(fixture.release_dir.join("SHA256SUMS"), b"").unwrap();
            }
            ChecksumMutation::Mismatch => {
                fs::write(
                    fixture.release_dir.join(fixture.asset_name()),
                    b"tampered\n",
                )
                .unwrap();
            }
        }
        let output = fixture.run();
        assert!(!output.status.success());
        assert_eq!(
            fs::read(fixture.install_dir.join("relay")).unwrap(),
            b"previous relay\n"
        );
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum ChecksumMutation {
    Missing,
    Mismatch,
}

#[cfg(unix)]
struct InstallerFixture {
    _temp: TempDir,
    fake_bin: PathBuf,
    release_dir: PathBuf,
    install_dir: PathBuf,
}

#[cfg(unix)]
impl InstallerFixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let fake_bin = temp.path().join("fake-bin");
        let release_dir = temp.path().join("release");
        let install_dir = temp.path().join("install");
        fs::create_dir_all(&fake_bin).unwrap();
        fs::create_dir_all(&release_dir).unwrap();
        write_executable(
            &fake_bin.join("curl"),
            r#"#!/usr/bin/env bash
set -euo pipefail
url=""
dest=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -o) dest="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
if [[ -n "${FAKE_CURL_LOG:-}" ]]; then
  printf '%s\n' "$url" >> "$FAKE_CURL_LOG"
fi
cp "${FAKE_RELEASE_DIR}/${url##*/}" "$dest"
"#,
        );
        write_executable(
            &fake_bin.join("uname"),
            r#"#!/usr/bin/env bash
case "${1:-}" in
  -s) printf '%s\n' "${FAKE_UNAME_S:-Linux}" ;;
  -m) printf '%s\n' "${FAKE_UNAME_M:-x86_64}" ;;
  *) exit 1 ;;
esac
"#,
        );
        let fixture = Self {
            _temp: temp,
            fake_bin,
            release_dir,
            install_dir,
        };
        fixture.write_release_assets();
        fixture
    }

    fn write_release_assets(&self) {
        let asset = self.release_dir.join(self.asset_name());
        fs::write(&asset, b"relay release binary\n").unwrap();
        fs::write(
            self.release_dir.join("SHA256SUMS"),
            format!("{}  {}\n", sha256(&asset), self.asset_name()),
        )
        .unwrap();
    }

    fn asset_name(&self) -> String {
        format!("relay-{TEST_VERSION}-linux-amd64")
    }

    fn preinstall_relay(&self) {
        fs::create_dir_all(&self.install_dir).unwrap();
        fs::write(self.install_dir.join("relay"), b"previous relay\n").unwrap();
    }

    fn assert_relay_installed(&self) {
        let path = self.install_dir.join("relay");
        assert_eq!(fs::read(&path).unwrap(), b"relay release binary\n");
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    fn run(&self) -> std::process::Output {
        self.command().output().unwrap()
    }

    fn temp_path(&self) -> &Path {
        self._temp.path()
    }

    fn fake_curl_log(&self) -> PathBuf {
        self._temp.path().join("curl-log")
    }

    fn rendered_installer(&self) -> PathBuf {
        let source = fs::read_to_string(installer_path()).unwrap();
        let marker = "default_version=\"\"";
        assert_eq!(source.matches(marker).count(), 1);
        let rendered = source.replacen(marker, &format!("default_version=\"{TEST_VERSION}\""), 1);
        let path = self._temp.path().join("relay-install.sh");
        fs::write(&path, rendered).unwrap();
        path
    }

    fn command(&self) -> Command {
        self.command_for_version(TEST_VERSION)
    }

    fn command_without_version(&self) -> Command {
        self.command_for(&installer_path(), false)
    }

    fn command_for_version(&self, version: &str) -> Command {
        let mut command = self.command_for(&installer_path(), false);
        command.env("RELAY_VERSION", version);
        command
    }

    fn command_for(&self, installer: &Path, set_version: bool) -> Command {
        let path = format!(
            "{}:{}",
            self.fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut command = Command::new("bash");
        command
            .arg(installer)
            .env("PATH", path)
            .env("FAKE_RELEASE_DIR", &self.release_dir)
            .env("FAKE_CURL_LOG", self.fake_curl_log())
            .env("RELAY_INSTALL_DIR", &self.install_dir);
        if set_version {
            command.env("RELAY_VERSION", TEST_VERSION);
        }
        command
    }

    fn command_from_stdin(&self, installer: &Path) -> Command {
        let mut command = self.command_for(Path::new("/dev/stdin"), false);
        command.stdin(Stdio::from(fs::File::open(installer).unwrap()));
        command
    }
}

#[cfg(unix)]
fn installer_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh")
}

#[cfg(unix)]
fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
fn sha256(path: &Path) -> String {
    for (program, args) in [("shasum", vec!["-a", "256"]), ("sha256sum", vec![])] {
        if let Ok(output) = Command::new(program).args(args).arg(path).output() {
            if output.status.success() {
                return String::from_utf8(output.stdout)
                    .unwrap()
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .to_string();
            }
        }
    }
    panic!("test needs shasum or sha256sum");
}
