// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_VERSION: &str = "v9.8.7";
const BINARIES: [&str; 2] = ["breg", "bregctl"];

#[test]
fn installer_switches_both_commands_through_one_toolset_pointer() {
    let fixture = InstallerFixture::new();

    let output = fixture.run(false);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_release_toolset_active();
    for binary in BINARIES {
        assert_eq!(
            fs::read_link(fixture.install_dir.join(binary)).unwrap(),
            PathBuf::from(format!(".breg-current/{binary}"))
        );
    }
    assert!(
        fs::symlink_metadata(fixture.install_dir.join(".breg-current"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn failed_atomic_pointer_switch_preserves_the_previous_toolset() {
    let fixture = InstallerFixture::new();
    fixture.preinstall_previous_toolset();

    let output = fixture.run(true);
    assert!(!output.status.success());
    for binary in BINARIES {
        assert_eq!(
            fs::read_to_string(fixture.install_dir.join(binary)).unwrap(),
            format!("{binary} previous binary\n")
        );
    }
}

struct InstallerFixture {
    root: PathBuf,
    release_dir: PathBuf,
    install_dir: PathBuf,
    fake_bin: PathBuf,
}

impl InstallerFixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "registry-breg-installer-test-{}-{unique}",
            std::process::id()
        ));
        let release_dir = root.join("release");
        let install_dir = root.join("install");
        let fake_bin = root.join("fake-bin");
        fs::create_dir_all(&release_dir).unwrap();
        fs::create_dir_all(&fake_bin).unwrap();
        let fixture = Self {
            root,
            release_dir,
            install_dir,
            fake_bin,
        };
        fixture.write_release_assets();
        fixture
    }

    fn write_release_assets(&self) {
        let suffix = platform_suffix();
        let mut sums = String::new();
        for binary in BINARIES {
            let asset = format!("{binary}-{TEST_VERSION}-{suffix}");
            let path = self.release_dir.join(&asset);
            fs::write(&path, format!("{binary} release binary\n")).unwrap();
            sums.push_str(&format!("{}  {asset}\n", sha256(&path)));
        }
        fs::write(self.release_dir.join("SHA256SUMS"), sums).unwrap();
    }

    fn preinstall_previous_toolset(&self) {
        fs::create_dir_all(&self.install_dir).unwrap();
        for binary in BINARIES {
            fs::write(
                self.install_dir.join(binary),
                format!("{binary} previous binary\n"),
            )
            .unwrap();
        }
    }

    fn run(&self, fail_final_pointer_switch: bool) -> Output {
        let mut command = Command::new("bash");
        command
            .arg(installer_path())
            .env("BREG_VERSION", TEST_VERSION)
            .env("BREG_ASSET_DIR", &self.release_dir)
            .env("BREG_INSTALL_DIR", &self.install_dir);
        if fail_final_pointer_switch {
            self.install_failing_mv();
            let path = format!(
                "{}:{}",
                self.fake_bin.display(),
                std::env::var("PATH").unwrap_or_default()
            );
            command
                .env("PATH", path)
                .env("REAL_MV", "/bin/mv")
                .env("FAKE_MV_COUNT", self.root.join("mv-count"));
        }
        command.output().unwrap()
    }

    fn install_failing_mv(&self) {
        let path = self.fake_bin.join("mv");
        fs::write(
            &path,
            r#"#!/usr/bin/env bash
set -euo pipefail
destination="${@: -1}"
if [[ "$destination" == */.breg-current ]]; then
  count=0
  if [[ -f "$FAKE_MV_COUNT" ]]; then
    read -r count < "$FAKE_MV_COUNT"
  fi
  count=$((count + 1))
  printf '%s\n' "$count" > "$FAKE_MV_COUNT"
  if [[ "$count" -eq 2 ]]; then
    exit 73
  fi
fi
exec "$REAL_MV" "$@"
"#,
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn assert_release_toolset_active(&self) {
        for binary in BINARIES {
            assert_eq!(
                fs::read_to_string(self.install_dir.join(binary)).unwrap(),
                format!("{binary} release binary\n")
            );
        }
    }
}

impl Drop for InstallerFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn installer_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh")
}

fn platform_suffix() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-amd64",
        ("linux", "aarch64") => "linux-arm64",
        ("macos", "aarch64") => "macos-arm64",
        platform => panic!("installer test runs on a supported platform, got {platform:?}"),
    }
}

fn sha256(path: &Path) -> String {
    for (program, args) in [("shasum", &["-a", "256"][..]), ("sha256sum", &[][..])] {
        if let Ok(output) = Command::new(program).args(args).arg(path).output() {
            if output.status.success() {
                return String::from_utf8(output.stdout)
                    .unwrap()
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .to_owned();
            }
        }
    }
    panic!("installer test needs shasum or sha256sum");
}
