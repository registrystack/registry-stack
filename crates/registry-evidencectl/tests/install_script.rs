// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use tempfile::TempDir;

const TEST_VERSION: &str = "v9.8.7";
const TEST_DEV_VERSION: &str = "v9.8.7-dev.12345.2";
const BINARIES: [&str; 3] = ["evidence", "evidencectl", "mint"];

#[cfg(unix)]
#[test]
fn installer_refuses_to_run_without_a_pinned_release() {
    let fixture = InstallerFixture::new();
    let output = fixture.command_without_version().output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("EVIDENCECTL_VERSION"), "stderr: {stderr}");
    assert!(
        !fixture.fake_curl_log().exists(),
        "must fail before download"
    );
}

#[cfg(unix)]
#[test]
fn installer_rejects_noncanonical_release_tags() {
    for tag in [
        "9.8.7",
        "v9.8",
        "latest",
        "v09.8.7",
        "v9.8.7-rc1",
        "v9.8.7-dev.1",
        "v9.8.7-dev.0.1",
        "v9.8.7-dev.1.0",
        "v9.8.7-dev.01.1",
        "v9.8.7-dev.1.01",
    ] {
        let fixture = InstallerFixture::for_release(tag);
        let output = fixture.run();
        assert!(!output.status.success(), "tag {tag} must be refused");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("non-canonical"),
            "tag {tag} stderr: {stderr}"
        );
        assert!(
            !fixture.fake_curl_log().exists(),
            "must fail before download"
        );
    }
}

#[cfg(unix)]
#[test]
fn installer_help_describes_the_toolset_and_verification_contract() {
    let fixture = InstallerFixture::new();
    let mut command = fixture.command_without_version();
    command.arg("--help");
    let output = command.output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "evidence runtime",
        "evidencectl adopter",
        "mint token issuer",
        "curl -fsSL https://github.com/registrystack/registry-stack/releases/latest/download/evidencectl-install.sh | bash",
        "SHA256SUMS",
        "EVIDENCECTL_ASSET_DIR",
        "release/VERIFY.md",
    ] {
        assert!(stdout.contains(expected), "help must mention {expected}");
    }
}

#[cfg(unix)]
#[test]
fn versioned_installer_asset_selects_its_own_release_without_an_override() {
    let fixture = InstallerFixture::new();
    let versioned = fixture
        .temp_path()
        .join(format!("evidencectl-{TEST_VERSION}-install.sh"));
    fs::copy(installer_path(), &versioned).unwrap();
    let output = fixture.command_for(&versioned, false).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_toolset_installed();
}

#[cfg(unix)]
#[test]
fn released_installer_supports_the_conventional_curl_pipe() {
    let fixture = InstallerFixture::new();
    let rendered = fixture.rendered_installer();
    let output = fixture.command_from_stdin(&rendered).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_toolset_installed();
}

#[cfg(unix)]
#[test]
fn development_installer_supports_the_curl_pipe_and_names_its_limit() {
    let fixture = InstallerFixture::for_release(TEST_DEV_VERSION);
    let rendered = fixture.rendered_installer();
    let output = fixture.command_from_stdin(&rendered).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_toolset_installed();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Development build"), "stdout: {stdout}");
    assert!(
        stdout.contains("unsupported prerelease"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("not signed"), "stdout: {stdout}");

    let downloads = fs::read_to_string(fixture.fake_curl_log()).unwrap();
    assert_eq!(downloads.lines().count(), BINARIES.len() + 1);
    assert!(
        downloads
            .lines()
            .all(|url| url.contains(&format!("/releases/download/{TEST_DEV_VERSION}/"))),
        "download URLs: {downloads}"
    );
}

#[cfg(unix)]
#[test]
fn versioned_development_installer_selects_its_own_prerelease() {
    let fixture = InstallerFixture::for_release(TEST_DEV_VERSION);
    let versioned = fixture
        .temp_path()
        .join(format!("evidencectl-{TEST_DEV_VERSION}-install.sh"));
    fs::copy(installer_path(), &versioned).unwrap();
    let output = fixture.command_for(&versioned, false).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_toolset_installed();
}

#[cfg(unix)]
#[test]
fn released_installer_rejects_a_mismatched_release_override_from_stdin() {
    let fixture = InstallerFixture::new();
    let rendered = fixture.rendered_installer();
    let mut command = fixture.command_from_stdin(&rendered);
    command.env("EVIDENCECTL_VERSION", "v1.2.3");
    let output = command.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Refusing a release override"),
        "stderr: {stderr}"
    );
    assert!(
        !fixture.fake_curl_log().exists(),
        "must fail before download"
    );
}

#[cfg(unix)]
#[test]
fn released_installer_rejects_a_filename_that_names_another_release() {
    let fixture = InstallerFixture::new();
    let rendered = fixture.rendered_installer();
    let mismatched = fixture.temp_path().join("evidencectl-v1.2.3-install.sh");
    fs::rename(rendered, &mismatched).unwrap();
    let output = fixture.command_for(&mismatched, false).output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("embedded release does not match its filename"),
        "stderr: {stderr}"
    );
    assert!(
        !fixture.fake_curl_log().exists(),
        "must fail before download"
    );
}

#[cfg(unix)]
#[test]
fn versioned_installer_asset_rejects_a_mismatched_release_override() {
    let fixture = InstallerFixture::new();
    let versioned = fixture
        .temp_path()
        .join(format!("evidencectl-{TEST_VERSION}-install.sh"));
    fs::copy(installer_path(), &versioned).unwrap();
    let mut command = fixture.command_for(&versioned, false);
    command.env("EVIDENCECTL_VERSION", "v1.2.3");
    let output = command.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Refusing a release override"),
        "stderr: {stderr}"
    );
    assert!(
        !fixture.fake_curl_log().exists(),
        "must fail before download"
    );
}

#[cfg(unix)]
#[test]
fn installer_checksum_verifies_and_installs_all_three_binaries() {
    let fixture = InstallerFixture::new();
    let output = fixture.run();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_toolset_installed();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Integrity checks passed"),
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
    command.env("EVIDENCECTL_ASSET_DIR", fixture.release_dir());
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_toolset_installed();
    assert!(
        !fixture.fake_curl_log().exists(),
        "asset-dir mode must not download"
    );
}

#[cfg(unix)]
#[test]
fn unsupported_platform_fails_before_download_without_a_partial_install() {
    let fixture = InstallerFixture::new();
    let mut command = fixture.command();
    command.env("FAKE_UNAME_S", "SunOS");
    let output = command.output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No prebuilt Evidence toolset asset"),
        "stderr: {stderr}"
    );
    assert!(
        !fixture.fake_curl_log().exists(),
        "must fail before download"
    );
    assert!(!fixture.install_dir().exists(), "nothing may be installed");
}

#[cfg(unix)]
#[test]
fn missing_checksum_entry_refuses_the_whole_install() {
    let fixture = InstallerFixture::new();
    fixture.rewrite_sums_without("evidencectl");
    let output = fixture.run();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SHA256SUMS has no entry"),
        "stderr: {stderr}"
    );
    fixture.assert_nothing_installed();
}

#[cfg(unix)]
#[test]
fn checksum_failure_preserves_the_existing_toolset() {
    let fixture = InstallerFixture::new();
    fixture.preinstall_previous_toolset();
    fixture.corrupt_release_asset("mint");
    let output = fixture.run();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Checksum verification failed"),
        "stderr: {stderr}"
    );
    fixture.assert_previous_toolset_intact();
}

#[cfg(unix)]
#[test]
fn partial_replacement_rolls_back_the_previous_toolset() {
    let fixture = InstallerFixture::new();
    fixture.preinstall_previous_toolset();
    let output = fixture.run_with_second_mv_failure();
    assert!(!output.status.success());
    fixture.assert_previous_toolset_intact();
}

// macOS ships bash 3.2, so `/usr/bin/env bash` finds a shell without
// associative arrays, `mapfile`, or case conversion on any Mac that has no
// newer bash installed. The installer advertises macOS arm64, and the runners
// that execute this suite carry bash 5, so the portable-construct guard has to
// be a property of the source text rather than of the interpreter under test.
#[cfg(unix)]
#[test]
fn installer_avoids_shell_constructs_stock_macos_bash_cannot_parse() {
    let source = fs::read_to_string(installer_path()).unwrap();
    for (construct, describe) in [
        ("declare -A", "associative arrays"),
        ("local -A", "associative arrays"),
        ("mapfile", "mapfile"),
        ("readarray", "readarray"),
        ("${!", "indirect or key expansion"),
        (",,}", "lowercase expansion"),
        ("^^}", "uppercase expansion"),
    ] {
        assert!(
            !source.contains(construct),
            "install.sh uses {describe} ('{construct}'), which bash 3.2 cannot parse"
        );
    }
}

#[cfg(unix)]
#[test]
fn installer_installs_under_stock_macos_bash() {
    let Some(bash) = stock_macos_bash() else {
        // Linux runners have no bash 3.2 to borrow. The construct guard above
        // is what protects this path there.
        return;
    };
    let fixture = InstallerFixture::new();
    let output = reinterpret(fixture.command(), &bash).output().unwrap();
    assert!(
        output.status.success(),
        "bash 3.2 install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.assert_toolset_installed();
}

#[cfg(unix)]
#[test]
fn stock_macos_bash_rollback_restores_the_previous_toolset() {
    let Some(bash) = stock_macos_bash() else {
        return;
    };
    let fixture = InstallerFixture::new();
    fixture.preinstall_previous_toolset();
    let output = reinterpret(fixture.mv_failure_command(), &bash)
        .output()
        .unwrap();
    assert!(!output.status.success());
    fixture.assert_previous_toolset_intact();
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
        Self::for_release(TEST_VERSION)
    }

    fn for_release(version: &str) -> Self {
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
            version: version.to_string(),
        };
        fixture.write_release_assets();
        fixture
    }

    fn write_release_assets(&self) {
        let mut checksums = Vec::new();
        for binary in BINARIES {
            let asset = self.asset_name(binary);
            let path = self.release_dir.join(&asset);
            fs::write(&path, format!("{binary} release binary\n")).unwrap();
            checksums.push(format!("{}  {}\n", sha256(&path), asset));
        }
        fs::write(self.release_dir.join("SHA256SUMS"), checksums.concat()).unwrap();
    }

    fn asset_name(&self, binary: &str) -> String {
        format!("{binary}-{}-linux-amd64", self.version)
    }

    fn rewrite_sums_without(&self, excluded: &str) {
        let mut checksums = Vec::new();
        for binary in BINARIES {
            if binary == excluded {
                continue;
            }
            let asset = self.asset_name(binary);
            let path = self.release_dir.join(&asset);
            checksums.push(format!("{}  {}\n", sha256(&path), asset));
        }
        fs::write(self.release_dir.join("SHA256SUMS"), checksums.concat()).unwrap();
    }

    fn corrupt_release_asset(&self, binary: &str) {
        let path = self.release_dir.join(self.asset_name(binary));
        fs::write(&path, b"tampered bytes\n").unwrap();
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

    fn assert_previous_toolset_intact(&self) {
        for binary in BINARIES {
            let contents = fs::read_to_string(self.install_dir.join(binary)).unwrap();
            assert_eq!(
                contents,
                format!("{binary} previous binary\n"),
                "{binary} must keep its previous contents"
            );
        }
    }

    fn assert_toolset_installed(&self) {
        for binary in BINARIES {
            let path = self.install_dir.join(binary);
            let contents = fs::read_to_string(&path).unwrap();
            assert_eq!(contents, format!("{binary} release binary\n"));
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755, "{binary} must be executable");
        }
    }

    fn assert_nothing_installed(&self) {
        for binary in BINARIES {
            assert!(
                !self.install_dir.join(binary).exists(),
                "{binary} must not be installed"
            );
        }
    }

    fn run(&self) -> std::process::Output {
        self.command().output().unwrap()
    }

    fn run_with_second_mv_failure(&self) -> std::process::Output {
        self.mv_failure_command().output().unwrap()
    }

    fn mv_failure_command(&self) -> Command {
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
if [[ "$count" -eq 2 ]]; then
  exit 73
fi
exec "$REAL_MV" "$@"
"#,
        );
        let mut command = self.command();
        command
            .env("FAKE_MV_COUNT_FILE", self._temp.path().join("mv-count"))
            .env("REAL_MV", "/bin/mv");
        command
    }

    fn fake_curl_log(&self) -> PathBuf {
        self._temp.path().join("curl-log")
    }

    fn temp_path(&self) -> &Path {
        self._temp.path()
    }

    fn rendered_installer(&self) -> PathBuf {
        let source = fs::read_to_string(installer_path()).unwrap();
        let marker = "default_version=\"\"";
        assert_eq!(source.matches(marker).count(), 1);
        let rendered = source.replacen(marker, &format!("default_version=\"{}\"", self.version), 1);
        let path = self._temp.path().join("evidencectl-install.sh");
        fs::write(&path, rendered).unwrap();
        path
    }

    fn release_dir(&self) -> &Path {
        &self.release_dir
    }

    fn install_dir(&self) -> &Path {
        &self.install_dir
    }

    fn command(&self) -> Command {
        self.command_for(&installer_path(), true)
    }

    fn command_without_version(&self) -> Command {
        self.command_for(&installer_path(), false)
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
            .env("EVIDENCECTL_INSTALL_DIR", &self.install_dir);
        if set_version {
            command.env("EVIDENCECTL_VERSION", &self.version);
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

/// `/bin/bash` when it is the bash 3.2 macOS ships, which is the interpreter a
/// Mac without Homebrew bash resolves `/usr/bin/env bash` to.
#[cfg(unix)]
fn stock_macos_bash() -> Option<PathBuf> {
    let path = PathBuf::from("/bin/bash");
    let output = Command::new(&path).arg("--version").output().ok()?;
    let banner = String::from_utf8_lossy(&output.stdout);
    banner.contains("version 3.").then_some(path)
}

/// Rebuild a prepared fixture command against a different shell, keeping its
/// arguments and environment.
#[cfg(unix)]
fn reinterpret(source: Command, shell: &Path) -> Command {
    let mut command = Command::new(shell);
    command.args(source.get_args());
    for (key, value) in source.get_envs() {
        match value {
            Some(value) => command.env(key, value),
            None => command.env_remove(key),
        };
    }
    command
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
