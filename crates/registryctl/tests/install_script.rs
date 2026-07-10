// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use tempfile::TempDir;

const TEST_VERSION: &str = "v9.8.7";
const TEST_LOCK_ASSET: &str = "registryctl-v9.8.7-image-lock.json";

#[test]
fn installer_rejects_shell_active_and_noncanonical_release_tags() {
    let installer = Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh");
    let hostile = "v999.0.0-$(touch${IFS}/tmp/registryctl-owned)";
    let multiline = "v999.0.0\n$(touch${IFS}/tmp/registryctl-owned)";

    for version in [hostile, multiline, "latest", "v1.2.3-rc1", "v01.2.3"] {
        let output = Command::new("bash")
            .arg(&installer)
            .env("REGISTRYCTL_VERSION", version)
            .output()
            .unwrap_or_else(|err| panic!("installer runs for rejected tag: {err}"));
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(!output.status.success(), "installer accepted {version}");
        assert!(
            stderr.contains("Refusing non-canonical registryctl release tag."),
            "unexpected rejection for {version}: {stderr}"
        );
        assert!(
            !stderr.contains(version),
            "installer echoed rejected tag {version}"
        );
        assert!(
            !stderr.contains("cargo install"),
            "installer emitted a fallback command"
        );
    }
}

#[test]
fn installer_help_describes_version_aware_release_assets() {
    let installer = Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh");
    let output = Command::new("bash")
        .arg(installer)
        .arg("--help")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(
        stdout.contains("Releases before v0.9.0 install the binary."),
        "{stdout}"
    );
    assert!(
        stdout.contains("Releases v0.9.0 and later install"),
        "{stdout}"
    );
    assert!(stdout.contains("matching release image lock"), "{stdout}");
}

#[cfg(unix)]
#[test]
fn installer_preserves_binary_only_compatibility_for_v0_8_4() {
    let fixture = InstallerFixture::for_release("v0.8.4", false);
    let output = fixture.run();

    assert!(
        output.status.success(),
        "legacy installer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        b"registryctl release binary\n",
        fs::read(fixture.install_dir.join("registryctl"))
            .unwrap()
            .as_slice()
    );
    assert!(!fixture
        .install_dir
        .join("registryctl-v0.8.4-image-lock.json")
        .exists());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout
            .contains("Integrity check passed: registryctl-v0.8.4-linux-amd64 matched SHA256SUMS."),
        "{stdout}"
    );
    assert!(!stdout.contains("release image lock installed"), "{stdout}");
    let downloads = fs::read_to_string(fixture.fake_curl_log()).unwrap();
    assert!(downloads.contains("/releases/download/v0.8.4/registryctl-v0.8.4-linux-amd64"));
    assert!(downloads.contains("/releases/download/v0.8.4/SHA256SUMS"));
    assert!(!downloads.contains("image-lock"), "{downloads}");
}

#[cfg(unix)]
#[test]
fn installer_checksum_verifies_and_installs_binary_with_matching_lock() {
    let fixture = InstallerFixture::new();
    let output = fixture.run();

    assert!(
        output.status.success(),
        "installer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        b"registryctl release binary\n",
        fs::read(fixture.install_dir.join("registryctl"))
            .unwrap()
            .as_slice()
    );
    assert_eq!(
        b"registryctl release image lock\n",
        fs::read(fixture.install_dir.join(TEST_LOCK_ASSET))
            .unwrap()
            .as_slice()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("matched SHA256SUMS"), "{stdout}");
    assert!(
        stdout.contains("Authenticity check not performed by this installer."),
        "{stdout}"
    );
    assert!(
        stdout.contains("Evidence availability varies by release, and v0.8.0 is unsigned."),
        "{stdout}"
    );
}

#[cfg(unix)]
#[test]
fn installer_checksum_failure_preserves_existing_binary_and_lock() {
    let fixture = InstallerFixture::new();
    fs::create_dir_all(&fixture.install_dir).unwrap();
    fs::write(
        fixture.install_dir.join("registryctl"),
        b"existing binary\n",
    )
    .unwrap();
    fs::write(
        fixture.install_dir.join(TEST_LOCK_ASSET),
        b"existing lock\n",
    )
    .unwrap();
    fs::write(
        fixture.release_dir.join(TEST_LOCK_ASSET),
        b"corrupted after checksums\n",
    )
    .unwrap();

    let output = fixture.run();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Checksum verification failed for registryctl-v9.8.7-image-lock.json"));
    assert_eq!(
        b"existing binary\n",
        fs::read(fixture.install_dir.join("registryctl"))
            .unwrap()
            .as_slice()
    );
    assert_eq!(
        b"existing lock\n",
        fs::read(fixture.install_dir.join(TEST_LOCK_ASSET))
            .unwrap()
            .as_slice()
    );
}

#[cfg(unix)]
#[test]
fn installer_rolls_back_pair_when_binary_replacement_fails_after_lock_replacement() {
    for existing in [false, true] {
        let fixture = InstallerFixture::new();
        if existing {
            fs::create_dir_all(&fixture.install_dir).unwrap();
            fs::write(
                fixture.install_dir.join("registryctl"),
                b"existing binary\n",
            )
            .unwrap();
            fs::write(
                fixture.install_dir.join(TEST_LOCK_ASSET),
                b"existing lock\n",
            )
            .unwrap();
        }

        let output = fixture.run_with_second_mv_failure();

        assert!(!output.status.success());
        let binary_path = fixture.install_dir.join("registryctl");
        let lock_path = fixture.install_dir.join(TEST_LOCK_ASSET);
        if existing {
            assert_eq!(
                b"existing binary\n",
                fs::read(&binary_path).unwrap().as_slice()
            );
            assert_eq!(b"existing lock\n", fs::read(&lock_path).unwrap().as_slice());
        } else {
            assert!(!binary_path.exists(), "rollback left a new binary behind");
            assert!(!lock_path.exists(), "rollback left a new image lock behind");
        }
        let moves = fs::read_to_string(fixture.fake_mv_log()).unwrap();
        let destinations = moves.lines().collect::<Vec<_>>();
        assert_eq!(2, destinations.len());
        assert!(destinations[0].ends_with(TEST_LOCK_ASSET), "{moves}");
        assert!(destinations[1].ends_with("/registryctl"), "{moves}");
    }
}

#[cfg(unix)]
#[test]
fn installer_term_during_install_restores_pair_and_exits_143() {
    let fixture = InstallerFixture::new();
    fs::create_dir_all(&fixture.install_dir).unwrap();
    fs::write(
        fixture.install_dir.join("registryctl"),
        b"existing binary\n",
    )
    .unwrap();
    fs::write(
        fixture.install_dir.join(TEST_LOCK_ASSET),
        b"existing lock\n",
    )
    .unwrap();

    let output = fixture.run_with_term_before_binary_replacement();

    assert_eq!(Some(143), output.status.code());
    assert_eq!(
        b"existing binary\n",
        fs::read(fixture.install_dir.join("registryctl"))
            .unwrap()
            .as_slice()
    );
    assert_eq!(
        b"existing lock\n",
        fs::read(fixture.install_dir.join(TEST_LOCK_ASSET))
            .unwrap()
            .as_slice()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("registryctl installed to"), "{stdout}");
    assert!(
        !stdout.contains("release image lock installed to"),
        "{stdout}"
    );
    let moves = fs::read_to_string(fixture.fake_mv_log()).unwrap();
    let destinations = moves.lines().collect::<Vec<_>>();
    assert_eq!(2, destinations.len());
    assert!(destinations[0].ends_with(TEST_LOCK_ASSET), "{moves}");
    assert!(destinations[1].ends_with("/registryctl"), "{moves}");
}

#[cfg(unix)]
#[test]
fn installer_cleans_staging_without_touching_pair_when_chmod_fails_before_mutation() {
    let fixture = InstallerFixture::new();
    fs::create_dir_all(&fixture.install_dir).unwrap();
    fs::write(
        fixture.install_dir.join("registryctl"),
        b"existing binary\n",
    )
    .unwrap();
    fs::write(
        fixture.install_dir.join(TEST_LOCK_ASSET),
        b"existing lock\n",
    )
    .unwrap();

    let output = fixture.run_with_staging_chmod_failure();

    assert!(!output.status.success());
    assert_eq!(
        b"existing binary\n",
        fs::read(fixture.install_dir.join("registryctl"))
            .unwrap()
            .as_slice()
    );
    assert_eq!(
        b"existing lock\n",
        fs::read(fixture.install_dir.join(TEST_LOCK_ASSET))
            .unwrap()
            .as_slice()
    );
    let names = fs::read_dir(&fixture.install_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(
        names
            .iter()
            .all(|name| !name.starts_with(".registryctl-install.")),
        "staging directory survived failure: {names:?}"
    );
}

#[cfg(unix)]
struct InstallerFixture {
    _temp: TempDir,
    fake_bin: PathBuf,
    release_dir: PathBuf,
    install_dir: PathBuf,
    version: String,
}

#[cfg(unix)]
impl InstallerFixture {
    fn new() -> Self {
        Self::for_release(TEST_VERSION, true)
    }

    fn for_release(version: &str, include_image_lock: bool) -> Self {
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
  -s) printf 'Linux\n' ;;
  -m) printf 'x86_64\n' ;;
  *) exit 1 ;;
esac
"#,
        );
        let binary_asset = format!("registryctl-{version}-linux-amd64");
        let lock_asset = format!("registryctl-{version}-image-lock.json");
        fs::write(
            release_dir.join(&binary_asset),
            b"registryctl release binary\n",
        )
        .unwrap();
        let mut checksums = vec![format!(
            "{}  {}\n",
            sha256(&release_dir.join(&binary_asset)),
            binary_asset,
        )];
        if include_image_lock {
            fs::write(
                release_dir.join(&lock_asset),
                b"registryctl release image lock\n",
            )
            .unwrap();
            checksums.push(format!(
                "{}  {}\n",
                sha256(&release_dir.join(&lock_asset)),
                lock_asset,
            ));
        }
        fs::write(release_dir.join("SHA256SUMS"), checksums.concat()).unwrap();
        Self {
            _temp: temp,
            fake_bin,
            release_dir,
            install_dir,
            version: version.to_string(),
        }
    }

    fn run(&self) -> std::process::Output {
        self.command().output().unwrap()
    }

    fn run_with_second_mv_failure(&self) -> std::process::Output {
        write_executable(
            &self.fake_bin.join("mv"),
            r#"#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "$FAKE_MV_COUNT_FILE" ]]; then
  read -r count < "$FAKE_MV_COUNT_FILE"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_MV_COUNT_FILE"
printf '%s\n' "${@: -1}" >> "$FAKE_MV_LOG"
if [[ "$count" -eq 2 ]]; then
  exit 73
fi
exec "$REAL_MV" "$@"
"#,
        );
        let mut command = self.command();
        command
            .env("FAKE_MV_COUNT_FILE", self._temp.path().join("mv-count"))
            .env("FAKE_MV_LOG", self.fake_mv_log())
            .env("REAL_MV", "/bin/mv");
        command.output().unwrap()
    }

    fn run_with_staging_chmod_failure(&self) -> std::process::Output {
        write_executable(
            &self.fake_bin.join("chmod"),
            "#!/usr/bin/env bash\nexit 74\n",
        );
        self.run()
    }

    fn run_with_term_before_binary_replacement(&self) -> std::process::Output {
        write_executable(
            &self.fake_bin.join("mv"),
            r#"#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "$FAKE_MV_COUNT_FILE" ]]; then
  read -r count < "$FAKE_MV_COUNT_FILE"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_MV_COUNT_FILE"
printf '%s\n' "${@: -1}" >> "$FAKE_MV_LOG"
if [[ "$count" -eq 2 ]]; then
  kill -TERM "$PPID"
  exit 0
fi
exec "$REAL_MV" "$@"
"#,
        );
        let mut command = self.command();
        command
            .env("FAKE_MV_COUNT_FILE", self._temp.path().join("mv-count"))
            .env("FAKE_MV_LOG", self.fake_mv_log())
            .env("REAL_MV", "/bin/mv");
        command.output().unwrap()
    }

    fn fake_mv_log(&self) -> PathBuf {
        self._temp.path().join("mv-log")
    }

    fn fake_curl_log(&self) -> PathBuf {
        self._temp.path().join("curl-log")
    }

    fn command(&self) -> Command {
        let installer = Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh");
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
            .env("REGISTRYCTL_VERSION", &self.version)
            .env("REGISTRYCTL_INSTALL_DIR", &self.install_dir);
        command
    }
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
